package cat.uvic.teknos.m09;

import java.io.IOException;
import java.util.Properties;

public class PropertiesFileTest {
    public static void main(String[] args) throws IOException {
        var properties = new Properties();
        properties.load(PropertiesFileTest.class.getResourceAsStream("/test.properties"));

        var ca1Attr1 = properties.get("cat1.attr2");

        System.out.println("cat1.attr2: " + ca1Attr1);
    }
}
