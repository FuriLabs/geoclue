/* vim: set et ts=8 sw=8: */
/*
 * Geoclue is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Geoclue is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Geoclue; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "gclue-nmea-utils.h"

/**
 * gclue_nmea_is_gga:
 * @msg: NMEA sentence
 *
 * Returns: whether given NMEA sentence is a GGA
 **/
gboolean
gclue_nmea_is_gga (const char *msg)
{
        return g_str_has_prefix (msg, "$GA" "GGA") ||  /* Galieo */
               g_str_has_prefix (msg, "$GB" "GGA") ||  /* BeiDou */
               g_str_has_prefix (msg, "$BD" "GGA") ||  /* BeiDou */
               g_str_has_prefix (msg, "$GL" "GGA") ||  /* GLONASS */
               g_str_has_prefix (msg, "$GN" "GGA") ||  /* GNSS (combined) */
               g_str_has_prefix (msg, "$GP" "GGA") ||  /* GPS, SBAS, QZSS */
               g_str_has_prefix (msg, "$QZ" "GGA");    /* QZSS */
}

/**
 * gclue_nmea_is_rmc:
 * @msg: NMEA sentence
 *
 * Returns: whether given NMEA sentence is a RMC
 **/
gboolean
gclue_nmea_is_rmc (const char *msg)
{
        return g_str_has_prefix (msg, "$GA" "RMC") ||  /* Galieo */
               g_str_has_prefix (msg, "$GB" "RMC") ||  /* BeiDou */
               g_str_has_prefix (msg, "$BD" "RMC") ||  /* BeiDou */
               g_str_has_prefix (msg, "$GL" "RMC") ||  /* GLONASS */
               g_str_has_prefix (msg, "$GN" "RMC") ||  /* GNSS (combined) */
               g_str_has_prefix (msg, "$GP" "RMC") ||  /* GPS, SBAS, QZSS */
               g_str_has_prefix (msg, "$QZ" "RMC");    /* QZSS */
}

/**
 * gclue_nmea_is_nmea:
 * @msg: sentence
 *
 * Returns: whether given sentence is valid NMEA
 **/
gboolean
gclue_nmea_is_nmea(const char *msg)
{
        return gclue_nmea_is_gga(msg) || gclue_nmea_is_rmc(msg);
}
