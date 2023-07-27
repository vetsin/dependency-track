package org.dependencytrack.parser.nexusiq;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

public class NeuxsIQParserTest { //extends PersistenceCapableTest {
    private JSONObject object;

    @Before
    public void setUp() throws IOException {
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/nexusiq.jsons/evaluation_response_npm.json")));
        this.object = new JSONObject(jsonString);
    }

    @Test
    public void testParserLoad() {
        var parser = new NexusIQEvaluationParser(this.object);
        var newObject = new JSONObject(object.toString());
        newObject.put("isError", true);
        newObject.put("errorMessage", "unit test error");

        Assert.assertThrows("unit test error", NexusIQEvaluationParser.EvaluationException.class, () -> {
            new NexusIQEvaluationParser(newObject);
        });
    }

    @Test
    public void testComponentMatch() throws NoSuchMethodException, MalformedPackageURLException, InvocationTargetException, IllegalAccessException {
        var parser = new NexusIQEvaluationParser(this.object);

        var c1 = new Component();
        var purl = new PackageURL("pkg:npm/npm@5.1.0");
        c1.setPurl(purl);

    }
}
