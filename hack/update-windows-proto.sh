#!/usr/bin/env bash

cd ../protocols/grpc
protoc --go_out=plugins=grpc:. windows.proto
