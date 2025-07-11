package Analyzer.Deserialization;

import lombok.Data;

import java.util.List;

@Data
public class TrafficInfo {
    private String id;

    private String url;

    private String method;

    private String content;

    private List<String> keys;

    private List<String> doubleWeightKeys;

}
