/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_CMD_DISPATCH_H
#define KHTOOLS_CMD_DISPATCH_H

int cmd_probe(int argc, char **argv);
int cmd_dump_syms(int argc, char **argv);
int cmd_finalize(int argc, char **argv);   /* phase 2 */
int cmd_assemble(int argc, char **argv);   /* phase 2 */
int cmd_patch(int argc, char **argv);      /* phase 4 */
int cmd_patch_image(int argc, char **argv); /* path-2 raw-Image variant */
int cmd_extract(int argc, char **argv);    /* phase 2 */
int cmd_list(int argc, char **argv);       /* phase 2 */
int cmd_verify(int argc, char **argv);     /* phase 4 */

#endif
