import com.android.tools.r8.Diagnostic;
import com.android.tools.r8.DiagnosticsHandler;
import com.android.tools.r8.naming.MapVersion;
import com.android.tools.r8.naming.mappinginformation.b;
import com.android.tools.r8.retrace.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** One bounded process and one complete-stack call preserve R8 contextual semantics. */
public final class RetraceBridge {
  private static final class Rejected extends RuntimeException {}
  private static final DiagnosticsHandler DIAGNOSTICS = new DiagnosticsHandler() {
    public void error(Diagnostic ignored) { throw new Rejected(); }
    public void warning(Diagnostic ignored) { throw new Rejected(); }
    public void info(Diagnostic ignored) { throw new Rejected(); }
  };

  private static String read(DataInputStream input, int maximum) throws IOException {
    int length = input.readInt();
    if (length < 0 || length > maximum) throw new Rejected();
    byte[] bytes = input.readNBytes(length);
    if (bytes.length != length) throw new Rejected();
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static String quoted(String value) {
    StringBuilder result = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '"' || c == '\\') result.append('\\').append(c);
      else if (c < 32 || Character.isSurrogate(c)) result.append(String.format("\\u%04x", (int)c));
      else result.append(c);
    }
    return result.append('"').toString();
  }

  private static void run(String path) throws Exception {
    String mapping;
    List<String> stack = new ArrayList<>();
    try (DataInputStream input = new DataInputStream(Files.newInputStream(Path.of(path)))) {
      mapping = read(input, 5 * 1024 * 1024);
      int count = input.readInt();
      if (count < 0 || count > 500) throw new Rejected();
      for (int i = 0; i < count; i++) stack.add(read(input, 4096));
      if (input.read() != -1) throw new Rejected();
    }
    var supplier = ProguardMappingSupplier.builder()
        .setProguardMapProducer(ProguardMapProducer.fromString(mapping))
        .setLoadAllDefinitions(true).setAllowExperimental(false).build();
    // The pinned distribution exposes MapVersionMappingInformation as b.
    // Fail compilation on an incompatible upgrade instead of reimplementing its parser.
    for (Object version : supplier.getMapVersions(DIAGNOSTICS)) {
      if (!(version instanceof b information) || information.o().isUnknown()
          || information.o().compareTo(MapVersion.STABLE) > 0) throw new Rejected();
    }
    var options = RetraceOptions.builder(DIAGNOSTICS).setMappingSupplier(supplier).build();
    var result = StringRetrace.create(options).retraceStackTrace(stack, RetraceStackTraceContext.empty());
    var groups = result.getResult();
    if (groups.size() != stack.size()) throw new Rejected();
    StringBuilder output = new StringBuilder("{\"schema_version\":1,\"groups\":[");
    int lines = 0;
    for (int i = 0; i < groups.size(); i++) {
      var group = groups.get(i);
      if (group.size() > 20) throw new Rejected();
      if (i != 0) output.append(',');
      output.append("{\"index\":").append(i).append(",\"ambiguous\":")
          .append(group.isAmbiguous()).append(",\"alternatives\":[");
      for (int j = 0; j < group.size(); j++) {
        if (j != 0) output.append(',');
        output.append("{\"lines\":[");
        var alternative = group.get(j);
        for (int k = 0; k < alternative.size(); k++) {
          String line = alternative.get(k);
          if (++lines > 2000 || line.getBytes(StandardCharsets.UTF_8).length > 16384) throw new Rejected();
          if (k != 0) output.append(',');
          output.append(quoted(line));
          if (output.length() > 1024 * 1024) throw new Rejected();
        }
        output.append("]}");
      }
      output.append("]}");
    }
    output.append("]}");
    byte[] bytes = output.toString().getBytes(StandardCharsets.UTF_8);
    if (bytes.length > 1024 * 1024) throw new Rejected();
    System.out.write(bytes);
  }

  public static void main(String[] args) {
    try {
      if (args.length != 1) throw new Rejected();
      run(args[0]);
    } catch (Throwable ignored) {
      // Diagnostics may contain the private mapping or exception message.
      System.exit(2);
    }
  }
}
