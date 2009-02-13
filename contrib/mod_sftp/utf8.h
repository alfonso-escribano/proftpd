/*
 * ProFTPD - mod_sftp UTF8 encoding
 * Copyright (c) 2008-2009 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id: utf8.h,v 1.2 2009-02-13 23:41:19 castaglia Exp $
 */

#ifndef MOD_SFTP_UTF8_H
#define MOD_SFTP_UTF8_H

char *sftp_utf8_decode_str(pool *p, const char *str);
char *sftp_utf8_encode_str(pool *p, const char *str);

int sftp_utf8_init(void);
int sftp_utf8_free(void);

#endif /* MOD_SFTP_UTF8_H */
