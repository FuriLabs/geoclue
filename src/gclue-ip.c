/* vim: set et ts=8 sw=8: */
/*
 * Copyright 2024 Teemu Ikonen
 *
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
 * Authors: Teemu Ikonen <tpikonen@mailbox.org>
 */

#include <stdlib.h>
#include <math.h>
#include <glib.h>
#include <string.h>
#include "config.h"
#include "gclue-ip.h"
#include "gclue-config.h"
#include "gclue-error.h"
#include "gclue-mozilla.h"

/**
 * SECTION:gclue-ip
 * @short_description: IP address based geolocation
 * @include: gclue-glib/gclue-ip.h
 *
 * Contains functions to determine the geolocation based on the IP address.
 **/

struct _GClueIpPrivate {
        GCancellable *cancellable;

        /* Ichnaea */
        GClueMozilla *mozilla;
        /* GMaps */
        GRegex *gregex;
};

G_DEFINE_TYPE_WITH_CODE (GClueIp,
                         gclue_ip,
                         GCLUE_TYPE_WEB_SOURCE,
                         G_ADD_PRIVATE (GClueIp))

/* Ichnaea method */

static SoupMessage *
ichnaea_create_query (GClueWebSource *source,
                      const char    **query_data_description,
                      GError        **error)
{
        GClueIp *ip = GCLUE_IP (source);

        return gclue_mozilla_create_query (ip->priv->mozilla, TRUE, TRUE,
                                           query_data_description, error);
}

static GClueLocation *
ichnaea_parse_response (GClueWebSource *source,
                        const char     *content,
                        GError        **error)
{
        const char *description = gclue_web_source_get_query_data_description (source);

        return gclue_mozilla_parse_response (content, description, error);
}

/* GMaps method */

#define GMAPS_URL "https://www.google.com/maps"
#define GMAPS_SCALE 1e7  /* meters */

static SoupMessage *
gmaps_create_query (GClueWebSource *source,
                    const char    **query_data_description,
                    GError        **error)
{
        g_autoptr(SoupMessage) query = NULL;

        query = soup_message_new ("GET", GMAPS_URL);
        if (query_data_description) {
                *query_data_description = "GMaps IP";
        }

        return g_steal_pointer (&query);
}

static double
round_to_1fig (double x)
{
        int zeros, base;

        zeros = (int) floor (log10 (x));
        base = pow (10, zeros);
        return round (x / base) * base;
}

static GClueLocation *
gmaps_parse_response (GClueWebSource *source,
                      const char *response,
                      GError    **error)
{
        GClueIp *ip = GCLUE_IP (source);
        g_autoptr(GMatchInfo) match_info = NULL;
        g_autofree char *locstring = NULL;
        double latitude, longitude, accuracy;
        guint64 zoom;
        char *lat_end, *lon_end, *zoom_end;
        GClueLocation *location;

        g_regex_match (ip->priv->gregex, response, 0, &match_info);
        if (!g_match_info_matches (match_info)) {
                g_warning ("No location found from GMaps response");
                return NULL;
        }
        locstring = g_match_info_fetch (match_info, 0);
        g_debug ("GMaps location string: %s", locstring);
        latitude = g_ascii_strtod (locstring + 7, &lat_end);
        longitude = g_ascii_strtod (lat_end + 3, &lon_end);
        zoom = g_ascii_strtoull (lon_end + 10, &zoom_end, 10);
        accuracy = round_to_1fig (zoom >= 1 ? GMAPS_SCALE / (1 << (zoom - 1)) :
                                              GMAPS_SCALE);
        g_debug ("Parsed GMaps values lat=%.8f, lon=%.8f, zoom=%lu",
                 latitude, longitude, zoom);
        if (latitude <= -180.0 || latitude > 180.0 ||
            longitude > 90.0 || longitude < -90.0 ||
            accuracy > GMAPS_SCALE || accuracy < 1.0) {
                g_warning ("GMaps coordinates are invalid: lat=%.8f, lon=%.8f, acc=%f",
                           latitude, longitude, accuracy);
                return NULL;
        }
        location = gclue_location_new (latitude, longitude, accuracy,
                                       gclue_web_source_get_query_data_description(source));

        return location;
}

/* GClueIp common */

static void
gclue_ip_finalize (GObject *gip)
{
        GClueIp *ip = (GClueIp *) gip;

        G_OBJECT_CLASS (gclue_ip_parent_class)->finalize (gip);

        g_cancellable_cancel (ip->priv->cancellable);

        g_clear_object (&ip->priv->cancellable);
        g_clear_object (&ip->priv->mozilla);
        g_clear_pointer (&ip->priv->gregex, g_regex_unref);
}

static GClueLocationSourceStartResult
gclue_ip_start (GClueLocationSource *source)
{
        GClueLocationSourceClass *base_class;
        GClueLocationSourceStartResult base_result;

        g_return_val_if_fail (GCLUE_IS_IP (source),
                              GCLUE_LOCATION_SOURCE_START_RESULT_FAILED);

        base_class = GCLUE_LOCATION_SOURCE_CLASS (gclue_ip_parent_class);
        base_result = base_class->start (source);
        if (base_result == GCLUE_LOCATION_SOURCE_START_RESULT_OK
            && gclue_location_source_get_location (source) != NULL) {
                g_debug ("Notifying old IP location");
                g_object_notify (G_OBJECT (source), "location");
        }

        return base_result;
}

static GClueAccuracyLevel
gclue_ip_get_available_accuracy_level (GClueWebSource *source,
                                       gboolean        net_available)
{
        if (!net_available)
                return GCLUE_ACCURACY_LEVEL_NONE;
        else
                return GCLUE_ACCURACY_LEVEL_CITY;
}

static void
gclue_ip_class_init (GClueIpClass *klass)
{
        GClueWebSourceClass *web_class = GCLUE_WEB_SOURCE_CLASS (klass);
        GClueLocationSourceClass *source_class = GCLUE_LOCATION_SOURCE_CLASS (klass);
        GObjectClass *ip_class = G_OBJECT_CLASS (klass);
        GClueConfig *config = gclue_config_get_singleton ();
        const char *method;

        source_class->start = gclue_ip_start;

        web_class->get_available_accuracy_level = gclue_ip_get_available_accuracy_level;
        method = gclue_config_get_ip_method (config);
        if (g_strcmp0 (method, "ichnaea") == 0) {
                web_class->create_query = ichnaea_create_query;
                web_class->parse_response = ichnaea_parse_response;
        } else if (g_strcmp0 (method, "gmaps") == 0) {
                web_class->create_query = gmaps_create_query;
                web_class->parse_response = gmaps_parse_response;
        } else {
                g_error ("Unknown IP method '%s'", method);
        }

        ip_class->finalize = gclue_ip_finalize;
}

static void
gclue_ip_init (GClueIp *ip)
{
        GClueWebSource *web_source = GCLUE_WEB_SOURCE (ip);
        GClueConfig *config = gclue_config_get_singleton ();
        const char *method;

        ip->priv = gclue_ip_get_instance_private (ip);

        ip->priv->cancellable = g_cancellable_new ();

        method = gclue_config_get_ip_method (config);
        if (g_strcmp0 (method, "ichnaea") == 0) {
                ip->priv->mozilla = gclue_mozilla_get_singleton ();
                gclue_web_source_set_locate_url
                        (web_source, gclue_mozilla_get_locate_url (ip->priv->mozilla));
        } else if (g_strcmp0 (method, "gmaps") == 0) {
                ip->priv->gregex = g_regex_new
                        ("center=[0-9\\.]*%2C[0-9\\.]*&amp;zoom=[0-9]*&amp;",
                         G_REGEX_DEFAULT, G_REGEX_MATCH_DEFAULT, NULL);
                gclue_web_source_set_locate_url (web_source, GMAPS_URL);
        } else {
                g_error ("Unknown IP method '%s'", method);
        }
}

/**
 * gclue_ip_get_singleton:
 *
 * Get the #GClueIp singleton.
 *
 * Returns: (transfer full): a new ref to #GClueIp. Use g_object_unref()
 * when done.
 **/
GClueIp *
gclue_ip_get_singleton (void)
{
        static GClueIp *ip = NULL;

        if (ip == NULL) {
                ip = g_object_new (GCLUE_TYPE_IP,
                                   "accuracy-level", GCLUE_ACCURACY_LEVEL_CITY,
                                   "compute-movement", FALSE,
                                   NULL);
                g_object_add_weak_pointer (G_OBJECT (ip),
                                           (gpointer) &ip);
        } else {
                g_object_ref (ip);
        }

        return ip;
}
