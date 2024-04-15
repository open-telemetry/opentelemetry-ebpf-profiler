/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

#include <unistd.h>

int main(int argc, char *argv[]) {
    // This process must not return (tests depend on it)
	return pause();
}
