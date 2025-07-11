package Analyzer.Representation;

import Analyzer.Deserialization.TrafficInfo;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.List;


public class ResultCell implements Comparable<ResultCell> {
    @JsonSerialize(using = MethodParserSerializer.class)
    public final MethodParser method; // only used in serializing method

    public final List<Edge> stack;
    public final String keyword;
    public int keywordsScore;
    public String id;


    public ResultCell(MethodParser method, List<Edge> stack, String keyword, TrafficInfo trafficInfo, int score) {
        this.method = method; // source method contains keyword
        this.stack = stack; // stack from source method to enc method
        this.keyword = keyword; // keyword of source method
        this.id = trafficInfo.getId();
        // how many methods in stack contains relevant keywords
        this.keywordsScore = score;
    }


    @Override
    public int compareTo(ResultCell obj) {
        // for comparison in the priority queue
        return this.keywordsScore - obj.keywordsScore;
    }

}
