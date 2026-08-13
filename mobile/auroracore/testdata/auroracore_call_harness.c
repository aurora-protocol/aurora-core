#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "auroracore.h"

static int read_full(uint8_t *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        size_t count = fread(buffer + offset, 1, length - offset, stdin);
        if (count == 0) {
            return feof(stdin) ? 0 : -1;
        }
        offset += count;
    }
    return 1;
}

static int write_full(const uint8_t *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        size_t count = fwrite(buffer + offset, 1, length - offset, stdout);
        if (count == 0) {
            return -1;
        }
        offset += count;
    }
    return fflush(stdout) == 0 ? 0 : -1;
}

static uint32_t read_u32(const uint8_t *buffer) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
}

static uint64_t read_u64(const uint8_t *buffer) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value = (value << 8) | buffer[index];
    }
    return value;
}

static void write_u32(uint8_t *buffer, uint32_t value) {
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)value;
}

int main(void) {
    for (;;) {
        uint8_t header[16];
        int header_result = read_full(header, sizeof(header));
        if (header_result == 0) {
            return 0;
        }
        if (header_result < 0) {
            return 1;
        }
        uint32_t operation = read_u32(header);
        uint64_t argument = read_u64(header + 4);
        uint32_t input_length = read_u32(header + 12);
        if (input_length > INT_MAX) {
            return 1;
        }
        uint8_t *input = NULL;
        if (operation == INT_MAX) {
            uint8_t sentinel = 0;
            int output_length = 0;
            uint8_t *output = AuroraCoreCall(0, &sentinel, INT_MAX, argument, &output_length);
            if (output_length <= 0 || output == NULL) {
                AuroraCoreZeroFree(output, output_length);
                return 1;
            }
            uint8_t output_header[4];
            write_u32(output_header, (uint32_t)output_length);
            if (write_full(output_header, sizeof(output_header)) != 0 || write_full(output, (size_t)output_length) != 0) {
                AuroraCoreZeroFree(output, output_length);
                return 1;
            }
            AuroraCoreZeroFree(output, output_length);
            continue;
        }
        if (input_length != 0) {
            input = malloc(input_length);
            if (input == NULL || read_full(input, input_length) != 1) {
                free(input);
                return 1;
            }
        }
        int output_length = 0;
        uint8_t *output = AuroraCoreCall((int)operation, input, (int)input_length, argument, &output_length);
        free(input);
        if (output_length <= 0 || output == NULL) {
            AuroraCoreZeroFree(output, output_length);
            return 1;
        }
        uint8_t output_header[4];
        write_u32(output_header, (uint32_t)output_length);
        if (write_full(output_header, sizeof(output_header)) != 0 || write_full(output, (size_t)output_length) != 0) {
            AuroraCoreZeroFree(output, output_length);
            return 1;
        }
        AuroraCoreZeroFree(output, output_length);
    }
}
