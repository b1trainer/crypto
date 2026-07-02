#!/bin/bash

set -a

source .env

set +a

mvn compile exec:java