package com.sentinel.av.core.engine;

public interface DetectionEngine {
    String getEngineId();
    String getEngineName();
    EngineResult evaluate(FileContext context);
}
