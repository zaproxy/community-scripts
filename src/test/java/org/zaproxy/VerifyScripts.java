/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import javax.script.Compilable;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.lang3.mutable.MutableInt;
import org.codehaus.groovy.jsr223.GroovyScriptEngineFactory;
import org.jruby.embed.jsr223.JRubyEngineFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestScript;
import org.python.core.Options;
import org.python.jsr223.PyScriptEngineFactory;

/** Verifies that the scripts are parsed without errors. */
class VerifyScripts {

    private static final int SCRIPT_TYPE_DIR_DEPTH = 3;

    private static List<Path> files;

    @BeforeAll
    static void readScriptDirs() throws Exception {
        readFiles();
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("allScripts")
    void shouldParseScript(
            Consumer<Reader> parser, @SuppressWarnings("unused") String script, Path path)
            throws Exception {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            parser.accept(reader);
        }
    }

    @AfterAll
    static void verifyAllFilesTested() {
        assertThat(files).as("Not all files were tested: %s", files).isEmpty();
    }

    private static Stream<Arguments> allScripts() {
        return Stream.of(
                        scriptsGroovy(),
                        scriptsJavaScript(),
                        scriptsPython(),
                        scriptsRuby(),
                        scriptsZest())
                .flatMap(s -> s);
    }

    private static Stream<Arguments> scriptsGroovy() {
        return testData(".groovy", (Compilable) new GroovyScriptEngineFactory().getScriptEngine());
    }

    private static Stream<Arguments> scriptsJavaScript() {
        if (!EnumSet.range(JRE.JAVA_8, JRE.JAVA_14).contains(JRE.currentVersion())) {
            // Nashorn is not bundled in Java 15+
            getFilesWithExtension(".js");
            return Stream.empty();
        }

        Compilable engine = (Compilable) new ScriptEngineManager().getEngineByName("ECMAScript");
        assertThat(engine).as("ECMAScript script engine exists.").isNotNull();
        return testData(".js", engine);
    }

    private static Stream<Arguments> scriptsPython() {
        Options.importSite = false;
        return testData(".py", (Compilable) new PyScriptEngineFactory().getScriptEngine());
    }

    private static Stream<Arguments> scriptsRuby() {
        if (!SystemUtils.IS_JAVA_1_8) {
            // Ref: https://github.com/zaproxy/zaproxy/issues/3944
            getFilesWithExtension(".rb");
            return Stream.empty();
        }
        return testData(".rb", (Compilable) new JRubyEngineFactory().getScriptEngine());
    }

    private static Stream<Arguments> scriptsZest() {
        return testData(
                ".zst",
                reader -> {
                    try {
                        assertThat(ZestJSON.fromString(IOUtils.toString(reader)))
                                .isInstanceOf(ZestScript.class);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
    }

    private static Stream<Arguments> testData(String extension, Compilable engine) {
        return testData(extension, parser(engine));
    }

    private static Stream<Arguments> testData(String extension, Consumer<Reader> parser) {
        return getFilesWithExtension(extension).stream()
                .map(
                        e ->
                                Arguments.of(
                                        parser,
                                        e.getParent().getParent().relativize(e).toString(),
                                        e));
    }

    private static Consumer<Reader> parser(Compilable engine) {
        return r -> {
            try {
                engine.compile(r);
            } catch (ScriptException e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static List<Path> getFilesWithExtension(String extension) {
        List<Path> filteredFiles = new ArrayList<>();
        files.removeIf(
                f -> {
                    if (f.getFileName().toString().endsWith(extension)) {
                        filteredFiles.add(f);
                        return true;
                    }
                    return false;
                });
        return filteredFiles;
    }

    private static void readFiles() throws Exception {
        Optional<String> path =
                Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                        .filter(e -> e.endsWith("/scripts"))
                        .findFirst();
        assertThat(path).as("The scripts directory was not found on the classpath.").isPresent();

        List<Path> unexpectedFiles = new ArrayList<>();
        MutableInt depth = new MutableInt();

        files = new ArrayList<>();
        Files.walkFileTree(
                Paths.get(path.get()),
                new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                            throws IOException {
                        depth.increment();
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (depth.intValue() != SCRIPT_TYPE_DIR_DEPTH) {
                            unexpectedFiles.add(file);
                            return FileVisitResult.CONTINUE;
                        }

                        if (!isExpectedNonScriptFile(file)) {
                            files.add(file);
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                            throws IOException {
                        depth.decrement();
                        return FileVisitResult.CONTINUE;
                    }
                });

        assertThat(unexpectedFiles).as("Files found not in a script type directory.").isEmpty();

        Collections.sort(files);
    }

    private static boolean isExpectedNonScriptFile(Path file) {
        String fileName = file.getFileName().toString().toLowerCase(Locale.ROOT);
        return fileName.endsWith(".md");
    }
}
