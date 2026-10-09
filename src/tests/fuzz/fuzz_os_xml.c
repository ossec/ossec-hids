/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * libFuzzer harness for os_xml (OSS-Fuzz / issue #1789).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os_xml.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[] = "/tmp/ossec-fuzz-os-xml-XXXXXX";
    int fd;
    FILE *fp;
    OS_XML xml;
    XML_NODE node;
    int i;

    if (data == NULL || size == 0) {
        return 0;
    }

    fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }

    fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        unlink(path);
        return 0;
    }

    if (fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        unlink(path);
        return 0;
    }
    fclose(fp);

    memset(&xml, 0, sizeof(xml));
    if (OS_ReadXML(path, &xml) < 0) {
        OS_ClearXML(&xml);
        unlink(path);
        return 0;
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (node == NULL) {
        OS_ClearXML(&xml);
        unlink(path);
        return 0;
    }

    i = 0;
    while (node[i]) {
        XML_NODE cnode;
        int j = 0;

        cnode = OS_GetElementsbyNode(&xml, node[i]);
        if (cnode == NULL) {
            i++;
            continue;
        }

        while (cnode[j]) {
            if (cnode[j]->attributes && cnode[j]->values) {
                int k = 0;

                while (cnode[j]->attributes[k]) {
                    k++;
                }
            }
            j++;
        }

        OS_ClearNode(cnode);
        i++;
    }

    OS_ClearNode(node);
    OS_ClearXML(&xml);
    unlink(path);
    return 0;
}
