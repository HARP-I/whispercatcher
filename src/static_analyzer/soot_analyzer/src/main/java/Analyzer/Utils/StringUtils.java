package Analyzer.Utils;

import org.apache.commons.text.StringEscapeUtils;

public class StringUtils {
    // private static final Logger logger = LoggerFactory.getLogger(StringUtils.class);

    public static String stringify(String input) {
        String trimmed = input.replace("\"", "").replace("\\\\", "\\");
        try {
            trimmed = StringEscapeUtils.unescapeJava(trimmed); // recover original string
        } catch (Exception ignore) {
        }
        return trimmed;
    }

}
