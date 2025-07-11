package Analyzer.Representation;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Objects;

public class Edge {
    @JsonSerialize(using = MethodParserSerializer.class)
    public MethodParser source;
    @JsonSerialize(using = MethodParserSerializer.class)
    public MethodParser target;

    public Edge(MethodParser source, MethodParser target) {
        this.source = source;
        this.target = target;
    }

    public Edge(MethodParser target) {
        this.target = target;
        this.source = null; // head
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;
        Edge edge = (Edge) obj;
        return Objects.equals(source, edge.source) && Objects.equals(target, edge.target);
    }

    @Override
    public int hashCode() {
        return Objects.hash(source, target);
    }

    @Override
    public String toString() {
        return source + "->" + target;
    }
}
