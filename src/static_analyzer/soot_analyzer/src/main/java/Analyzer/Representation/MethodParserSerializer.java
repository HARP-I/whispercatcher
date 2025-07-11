package Analyzer.Representation;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

public class MethodParserSerializer extends StdSerializer<MethodParser> {

    protected MethodParserSerializer() {
        super(MethodParser.class);
    }

    @Override
    public void serialize(MethodParser methodParser, JsonGenerator jsonGenerator,
                          SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(methodParser.toString());
    }
}
