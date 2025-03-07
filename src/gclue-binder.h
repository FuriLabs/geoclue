/* vim: set et ts=8 sw=8: */
/*
 * Copyright (C) 2015 Jolla Ltd.
 * Copyright (C) 2025 Furi Labs
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
 * Authors: Matti Lehtimäki <matti.lehtimaki@gmail.com>
 *          Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef GCLUE_BINDER_H
#define GCLUE_BINDER_H

#include <gio/gio.h>
#include <gbinder.h>

#include "gclue-binder-types.h"

G_BEGIN_DECLS

GType gclue_binder_get_type (void) G_GNUC_CONST;

#define GCLUE_TYPE_BINDER            (gclue_binder_get_type ())
#define GCLUE_BINDER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCLUE_TYPE_BINDER, GClueBinder))
#define GCLUE_IS_BINDER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCLUE_TYPE_BINDER))
#define GCLUE_BINDER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GCLUE_TYPE_BINDER, GClueBinderClass))
#define GCLUE_IS_BINDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GCLUE_TYPE_BINDER))
#define GCLUE_BINDER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GCLUE_TYPE_BINDER, GClueBinderClass))

typedef struct _GClueBinder        GClueBinder;
typedef struct _GClueBinderClass   GClueBinderClass;
typedef struct _GClueBinderPrivate GClueBinderPrivate;

struct _GClueBinder {
        /* <private> */
        GObject parent_instance;
        GClueBinderPrivate *priv;
};

struct _GClueBinderClass {
        /* <private> */
        GObjectClass parent_class;
};

GClueBinder* gclue_binder_get_singleton (void);

gboolean gclue_binder_gnssInit (GClueBinder *binder);
gboolean gclue_binder_gnssStart (GClueBinder *binder);
gboolean gclue_binder_gnssStop (GClueBinder *binder);
void gclue_binder_gnssCleanup (GClueBinder *binder);

gboolean gclue_binder_gnssInjectLocation (GClueBinder *binder,
                                          double latitudeDegrees,
                                          double longitudeDegrees,
                                          float accuracyMeters);

gboolean gclue_binder_gnssSetPositionMode (GClueBinder *binder,
                                           BinderGnssPositionMode mode,
                                           BinderGnssPositionRecurrence recurrence,
                                           guint32 minIntervalMs,
                                           guint32 preferredAccuracyMeters,
                                           guint32 preferredTimeMs);

void gclue_binder_gnssDebugInit (GClueBinder *binder);
void gclue_binder_gnssNiInit (GClueBinder *binder);
void gclue_binder_gnssXtraInit (GClueBinder *binder);
void gclue_binder_aGnssInit (GClueBinder *binder);
void gclue_binder_aGnssRilInit (GClueBinder *binder);

G_END_DECLS

#endif /* GCLUE_BINDER_H */
