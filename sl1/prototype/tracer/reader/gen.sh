#!/bin/bash
protoc -I../schema --python_out=. ../schema/Trace.proto
