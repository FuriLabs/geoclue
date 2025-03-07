/* vim: set et ts=8 sw=8: */
/*
 * Copyright 2021 The Droidian Project
 * Copyright 2025 Furi Labs
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
 * Authors: Erfan Abdi <erfangplus@gmail.com>
 *          Bardia Moshiri <bardia@furilabs.com>
 */

#include <stdlib.h>
#include <glib.h>
#include "gclue-binder.h"
#include "gclue-binder-source.h"
#include "gclue-binder.h"
#include "gclue-location.h"
#include "config.h"
#include "gclue-enum-types.h"

struct _GClueBinderSourcePrivate {
        GClueBinder *binder;
        GCancellable *cancellable;
};

G_DEFINE_TYPE_WITH_CODE (GClueBinderSource,
                         gclue_binder_source,
                         GCLUE_TYPE_LOCATION_SOURCE,
                         G_ADD_PRIVATE (GClueBinderSource))

static GClueLocationSourceStartResult
gclue_binder_source_start (GClueLocationSource *source);
static GClueLocationSourceStopResult
gclue_binder_source_stop (GClueLocationSource *source);

static void
connect_to_service (GClueBinderSource *source);
static void
disconnect_from_service (GClueBinderSource *source);

static void
on_location_changed (GObject    *gobject,
                     GParamSpec *pspec,
                     gpointer    user_data)
{
        GClueBinder *binder = GCLUE_BINDER (user_data);
        GClueLocationSource *source = GCLUE_LOCATION_SOURCE (gobject);
        GClueLocation *location;

        location = gclue_location_source_get_location (source);
        if (location == NULL)
                return;

        gclue_binder_gnssInjectLocation (binder,
                                         gclue_location_get_latitude(location),
                                         gclue_location_get_longitude(location),
                                         gclue_location_get_accuracy(location));
}

static void
on_set_location (GClueBinder *binder,
                 gpointer     loc_p,
                 gpointer     user_data)
{
        GClueBinderSource *source = GCLUE_BINDER_SOURCE (user_data);
        GClueBinderLocation *loc = (GClueBinderLocation *) loc_p;

        GClueLocation *location;
        location = gclue_location_new_full (loc->latitude,
                                            loc->longitude,
                                            loc->accuracy->horizontal,
                                            loc->speed,
                                            loc->direction,
                                            loc->altitude,
                                            loc->timestamp / 1000,
                                            "Binder location");

        gclue_location_source_set_location (GCLUE_LOCATION_SOURCE (source), location);
}

static void
connect_to_service (GClueBinderSource *source)
{
        GClueBinderSourcePrivate *priv = source->priv;

        g_cancellable_reset (priv->cancellable);

        g_signal_connect (G_OBJECT (source),
                          "notify::location",
                          G_CALLBACK (on_location_changed),
                          priv->binder);

        g_signal_connect (priv->binder,
                          "setLocation",
                          G_CALLBACK (on_set_location),
                          source);

        gclue_binder_gnssSetPositionMode (priv->binder,
                                          BINDER_GNSS_POSITION_MODE_STANDALONE,
                                          BINDER_GNSS_POSITION_RECURRENCE_PERIODIC,
                                          1000, 0, 0);

        gclue_binder_gnssStart (priv->binder);
}

static void
disconnect_from_service (GClueBinderSource *source)
{
        GClueBinderSourcePrivate *priv = source->priv;

        g_cancellable_cancel (priv->cancellable);

        g_signal_handlers_disconnect_by_func (G_OBJECT (source),
                                              G_CALLBACK (on_location_changed),
                                              priv->binder);

        gclue_binder_gnssStop (priv->binder);
}

static void
gclue_binder_source_finalize (GObject *gbinder)
{
        GClueBinderSourcePrivate *priv = GCLUE_BINDER_SOURCE (gbinder)->priv;

        gclue_binder_gnssCleanup (priv->binder);

        G_OBJECT_CLASS (gclue_binder_source_parent_class)->finalize (gbinder);

        g_clear_object (&priv->cancellable);
        g_clear_object (&priv->binder);
}

static void
gclue_binder_source_class_init (GClueBinderSourceClass *klass)
{
        GClueLocationSourceClass *source_class = GCLUE_LOCATION_SOURCE_CLASS (klass);
        GObjectClass *gbinder_class = G_OBJECT_CLASS (klass);

        gbinder_class->finalize = gclue_binder_source_finalize;

        source_class->start = gclue_binder_source_start;
        source_class->stop = gclue_binder_source_stop;
}

static void
gclue_binder_source_init (GClueBinderSource *source)
{
        GClueBinderSourcePrivate *priv;

        source->priv = gclue_binder_source_get_instance_private (source);
        priv = source->priv;

        priv->cancellable = g_cancellable_new ();
        priv->binder = gclue_binder_get_singleton ();

        GClueAccuracyLevel level;
        level = GCLUE_ACCURACY_LEVEL_EXACT;
        g_debug ("Setting accuracy level to %s: %u",
                 G_OBJECT_TYPE_NAME (source), level);
        g_object_set (G_OBJECT (source),
                      "available-accuracy-level", level, NULL);

        gclue_binder_gnssInit (priv->binder);
        gclue_binder_aGnssInit (priv->binder);
        gclue_binder_gnssNiInit (priv->binder);
        gclue_binder_aGnssRilInit (priv->binder);
        gclue_binder_gnssXtraInit (priv->binder);
        gclue_binder_gnssDebugInit (priv->binder);
}

/**
 * gclue_binder_source_get_singleton:
 *
 * Get the #GClueBinderSource singleton.
 *
 * Returns: (transfer full): a new ref to #GClueBinderSource. Use g_object_unref()
 * when done.
 **/
GClueBinderSource *
gclue_binder_source_get_singleton (void)
{
        static GClueBinderSource *source = NULL;

        if (source == NULL) {
                source = g_object_new (GCLUE_TYPE_BINDER_SOURCE, NULL);
                g_object_add_weak_pointer (G_OBJECT (source),
                                           (gpointer) &source);
        } else
                g_object_ref (source);

        return source;
}

static GClueLocationSourceStartResult
gclue_binder_source_start (GClueLocationSource *source)
{
        GClueLocationSourceClass *base_class;
        GClueLocationSourceStartResult base_result;

        g_return_val_if_fail (GCLUE_IS_BINDER_SOURCE (source),
                              GCLUE_LOCATION_SOURCE_START_RESULT_FAILED);

        base_class = GCLUE_LOCATION_SOURCE_CLASS (gclue_binder_source_parent_class);
        base_result = base_class->start (source);
        if (base_result == GCLUE_LOCATION_SOURCE_START_RESULT_FAILED)
                return base_result;

        connect_to_service (GCLUE_BINDER_SOURCE (source));

        return TRUE;
}

static GClueLocationSourceStopResult
gclue_binder_source_stop (GClueLocationSource *source)
{
        GClueLocationSourceClass *base_class;
        GClueLocationSourceStopResult base_result;

        g_return_val_if_fail (GCLUE_IS_BINDER_SOURCE (source), FALSE);

        base_class = GCLUE_LOCATION_SOURCE_CLASS (gclue_binder_source_parent_class);
        base_result = base_class->stop (source);
        if (base_result == GCLUE_LOCATION_SOURCE_STOP_RESULT_STILL_USED)
                return base_result;

        disconnect_from_service (GCLUE_BINDER_SOURCE (source));

        return TRUE;
}
