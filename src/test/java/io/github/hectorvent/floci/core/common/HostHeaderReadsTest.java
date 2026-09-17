package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The request host is read in one place, {@link RequestHost}. Any other read of the {@code Host}
 * header under {@code src/main/java} misses the HTTP/2 {@code :authority} and fails here.
 */
class HostHeaderReadsTest {

    private static final Pattern HOST_READ = Pattern.compile(
            "getHeaderString\\(\\s*\"host\"\\s*\\)"
                    + "|getHeader\\(\\s*\"host\"\\s*\\)"
                    + "|getHeader(String)?\\(\\s*HttpHeaders\\.HOST\\s*\\)"
                    + "|@HeaderParam\\(\\s*\"host\"\\s*\\)",
            Pattern.CASE_INSENSITIVE);

    @Test
    void onlyRequestHostReadsTheHostHeader() throws IOException {
        Path root = Path.of("src/main/java");
        assertTrue(Files.isDirectory(root), "run from the fork's root: " + root.toAbsolutePath());
        List<String> offenders = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.getFileName().toString().equals("RequestHost.java"))
                    .sorted()
                    .forEach(p -> scan(p, offenders));
        }
        assertTrue(offenders.isEmpty(),
                "Read the request host through RequestHost, not the Host header:\n"
                        + String.join("\n", offenders));
    }

    private static void scan(Path file, List<String> offenders) {
        try {
            List<String> lines = Files.readAllLines(file);
            for (int i = 0; i < lines.size(); i++) {
                if (HOST_READ.matcher(lines.get(i)).find()) {
                    offenders.add(file + ":" + (i + 1) + ": " + lines.get(i).trim());
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
