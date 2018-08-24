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
import java.io.Reader;
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
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.script.Compilable;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.python.jsr223.PyScriptEngineFactory;

/** Verifies that the scripts are parsed without errors. */
class VerifyScripts {

    private static List<Path> files;

    @BeforeAll
    private static void readScriptDirs() throws Exception {
        readFiles();
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource({"scriptsJavaScript", "scriptsPython"})
    void shouldParseScript(
            Consumer<Reader> parser, @SuppressWarnings("unused") String script, Path path)
            throws Exception {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            parser.accept(reader);
        }
    }

    private static Stream<Arguments> scriptsJavaScript() {
        Compilable engine = (Compilable) new ScriptEngineManager().getEngineByName("ECMAScript");
        assertThat(engine).as("ECMAScript script engine exists.").isNotNull();
        return testData(".js", engine);
    }

    private static Stream<Arguments> scriptsPython() {
        return testData(".py", (Compilable) new PyScriptEngineFactory().getScriptEngine());
    }

    private static Stream<Arguments> testData(String extension, Compilable engine) {
        return testData(extension, parser(engine));
    }

    private static Stream<Arguments> testData(String extension, Consumer<Reader> parser) {
        List<Path> testFiles = getFilesWithExtension(extension);
        assertThat(testFiles).as("No scripts found with extension %s", extension).isNotEmpty();
        return testFiles
                .stream()
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
        return files.stream()
                .filter(f -> f.getFileName().toString().endsWith(extension))
                .collect(Collectors.toList());
    }

    private static void readFiles() throws Exception {
        Optional<String> path =
                Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                        .filter(e -> e.endsWith("/scripts"))
                        .findFirst();
        assertThat(path).as("The scripts directory was not found on the classpath.").isPresent();

        files = new ArrayList<>();
        Files.walkFileTree(
                Paths.get(path.get()),
                new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        files.add(file);
                        return FileVisitResult.CONTINUE;
                    }
                });

        Collections.sort(files);
    }
}
