package Analyzer.Representation;

public class MethodParserWithDepth {
    public final MethodParser methodParser;
    public int depth;

    public MethodParserWithDepth(MethodParser methodParser, int depth) {
        this.methodParser = methodParser;
        this.depth = depth;
    }
}
