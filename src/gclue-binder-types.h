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

#ifndef GCLUE_BINDER_TYPES_H
#define GCLUE_BINDER_TYPES_H

#include <glib.h>

G_BEGIN_DECLS

#define ALIGNED(x) __attribute__ ((aligned(x)))

typedef struct {
        double horizontal;
        double vertical;
} GClueBinderAccuracy;

typedef struct {
        gint64 timestamp;
        double latitude;
        double longitude;
        double altitude;
        double speed;
        double direction;
        double climb;
        GClueBinderAccuracy* accuracy;
} GClueBinderLocation;

typedef struct {
        int prn;
        int elevation;
        int azimuth;
        int snr;
} GClueBinderSatelliteInfo;

/** Milliseconds since January 1, 1970 */
typedef int64_t BinderGnssUtcTime;

/** Requested operational mode for GPS operation. */
typedef guint32 BinderGnssPositionMode;

/** Requested recurrence mode for GPS operation. */
typedef guint32 BinderGnssPositionRecurrence;

/** GPS status event values. */
typedef guint16 BinderGnssStatusValue;

/** Flags to indicate which values are valid in a GpsLocation. */
typedef guint16 BinderGnssLocationFlags;

/**
 * Flags used to specify which aiding data to delete when calling
 * delete_aiding_data().
 */
typedef guint16 BinderGnssAidingData;

/** AGPS type */
typedef guint16 BinderAGnssType;

typedef guint16 BinderAGnssSetIDType;

typedef guint16 BinderApnIpType;

typedef int16_t BinderAGpsBearerType;

/**
 * BinderGnssNiType constants
 */
typedef guint32 BinderGnssNiType;

/**
 * BinderGnssNiNotifyFlags constants
 */
typedef guint32 BinderGnssNiNotifyFlags;

/**
 * GPS NI responses, used to define the response in
 * NI structures
 */
typedef int BinderGnssUserResponseType;

/**
 * NI data encoding scheme
 */
typedef int BinderGnssNiEncodingType;

/** AGPS status event values. */
typedef guint16 BinderAGnssStatusValue;

typedef guint16 BinderAGnssRefLocationType;

typedef int BinderNetworkType;

enum {
    BINDER_GNSS_POSITION_MODE_STANDALONE,
    BINDER_GNSS_POSITION_MODE_MS_BASED = 1,
    BINDER_GNSS_POSITION_MODE_MS_ASSISTED = 2,
};

enum {
    BINDER_GNSS_POSITION_RECURRENCE_PERIODIC,
    BINDER_GNSS_POSITION_RECURRENCE_SINGLE = 1,
};

enum {
    BINDER_AGNSS_TYPE_SUPL = 1,
    BINDER_AGNSS_TYPE_C2K = 2,
};

enum {
    BINDER_GNSS_REQUEST_AGNSS_DATA_CONN = 1,
    BINDER_GNSS_RELEASE_AGNSS_DATA_CONN = 2,
    BINDER_GNSS_AGNSS_DATA_CONNECTED = 3,
    BINDER_GNSS_AGNSS_DATA_CONN_DONE = 4,
    BINDER_GNSS_AGNSS_DATA_CONN_FAILED = 5,
};

enum {
        UNKNOWN = 0,
        GPS = 1,
        SBAS = 2,
        GLONASS = 3,
        QZSS = 4,
        BEIDOU = 5,
        GALILEO = 6,
};

enum {
        HAS_LAT_LONG = 1, // 0x0001
        HAS_ALTITUDE = 2, // 0x0002
        HAS_SPEED = 4, // 0x0004
        HAS_BEARING = 8, // 0x0008
        HAS_HORIZONTAL_ACCURACY = 16, // 0x0010
        HAS_VERTICAL_ACCURACY = 32, // 0x0020
        HAS_SPEED_ACCURACY = 64, // 0x0040
        HAS_BEARING_ACCURACY = 128, // 0x0080
};

enum {
        BINDER_GNSS_SV_FLAGS_NONE = 0,
        BINDER_GNSS_SV_FLAGS_HAS_EPHEMERIS_DATA = 1, // (1 << 0)
        BINDER_GNSS_SV_FLAGS_HAS_ALMANAC_DATA = 2, // (1 << 1)
        BINDER_GNSS_SV_FLAGS_USED_IN_FIX = 4, // (1 << 2)
        BINDER_GNSS_SV_FLAGS_HAS_CARRIER_FREQUENCY = 8, // (1 << 3)
};

typedef struct gnss_location {
        guint16 gnssLocationFlags ALIGNED(2);
        gdouble latitudeDegrees ALIGNED(8);
        gdouble longitudeDegrees ALIGNED(8);
        gdouble altitudeMeters ALIGNED(8);
        gfloat speedMetersPerSec ALIGNED(4);
        gfloat bearingDegrees ALIGNED(4);
        gfloat horizontalAccuracyMeters ALIGNED(4);
        gfloat verticalAccuracyMeters ALIGNED(4);
        gfloat speedAccuracyMetersPerSecond ALIGNED(4);
        gfloat bearingAccuracyDegrees ALIGNED(4);
        gint64 timestamp ALIGNED(8);
} ALIGNED(8) GnssLocation;

G_STATIC_ASSERT(sizeof(GnssLocation) == 64);

typedef struct gnss_sv_info {
        gint16 svid ALIGNED(2);
        guint8 constellation ALIGNED(1);
        gfloat cN0Dbhz ALIGNED(4);
        gfloat elevationDegrees ALIGNED(4);
        gfloat azimuthDegrees ALIGNED(4);
        gfloat carrierFrequencyHz ALIGNED(4);
        guint8 svFlag ALIGNED(1);
} ALIGNED(4) GnssSvInfo;

G_STATIC_ASSERT(sizeof(GnssSvInfo) == 24);

typedef struct gnss_sv_status {
        gint32 numSvs ALIGNED(4);
        GnssSvInfo gnssSvList[64] ALIGNED(4);
} ALIGNED(4) GnssSvStatus;

G_STATIC_ASSERT(sizeof(GnssSvStatus) == 1540);

typedef guint8 AGnssType;
typedef guint8 AGnssStatusValue;

enum {
        BINDER_GNSS_STATUS_NONE = 0,
        BINDER_GNSS_STATUS_SESSION_BEGIN = 1,
        BINDER_GNSS_STATUS_SESSION_END = 2,
        BINDER_GNSS_STATUS_ENGINE_ON = 3,
        BINDER_GNSS_STATUS_ENGINE_OFF = 4,
};

enum {
        BINDER_GNSS_LOCATION_HAS_LAT_LONG = 1, // 0x0001
        BINDER_GNSS_LOCATION_HAS_ALTITUDE = 2, // 0x0002
        BINDER_GNSS_LOCATION_HAS_SPEED = 4, // 0x0004
        BINDER_GNSS_LOCATION_HAS_BEARING = 8, // 0x0008
        BINDER_GNSS_LOCATION_HAS_HORIZONTAL_ACCURACY = 16, // 0x0010
        BINDER_GNSS_LOCATION_HAS_VERTICAL_ACCURACY = 32, // 0x0020
        BINDER_GNSS_LOCATION_HAS_SPEED_ACCURACY = 64, // 0x0040
        BINDER_GNSS_LOCATION_HAS_BEARING_ACCURACY = 128, // 0x0080
};

enum Capabilities : guint32 {
        SCHEDULING                      = 1 << 0,
        MSB                             = 1 << 1,
        MSA                             = 1 << 2,
        SINGLE_SHOT                     = 1 << 3,
        ON_DEMAND_TIME                  = 1 << 4,
        GEOFENCING                      = 1 << 5,
        MEASUREMENTS                    = 1 << 6,
        NAV_MESSAGES                    = 1 << 7
};

enum ID : guint32 {
        IMSI    = 1 << 0L,
        MSISDN  = 1 << 1L
};

enum SetIDType : guint8 {
        SETID_NONE    = 0,
        SETID_IMSI    = 1,
        SETID_MSISDM  = 2
};

enum AGnssStatusValue : guint8 {
        /** GNSS requests data connection for AGNSS. */
        REQUEST_AGNSS_DATA_CONN  = 1,
        /** GNSS releases the AGNSS data connection. */
        RELEASE_AGNSS_DATA_CONN  = 2,
        /** AGNSS data connection initiated */
        AGNSS_STATUS_DATA_CONNECTED     = 3,
        /** AGNSS data connection completed */
        AGNSS_STATUS_DATA_CONN_DONE     = 4,
        /** AGNSS data connection failed */
        AGNSS_STATUS_DATA_CONN_FAILED   = 5
};

enum AGnssType : guint8 {
        TYPE_SUPL         = 1,
        TYPE_C2K          = 2,
        TYPE_SUPL_EIMS    = 3,
        TYPE_SUPL_IMS     = 4
};

typedef struct agnss_status_ip_v4 {
        AGnssType type ALIGNED(1);
        AGnssStatusValue status ALIGNED(1);
        gint32 ipV4Addr ALIGNED(4);
} ALIGNED(4) AGnssStatusIpV4;

G_STATIC_ASSERT(sizeof(AGnssStatusIpV4) == 8);

typedef struct agnss_status_ip_v6 {
        AGnssType type ALIGNED(1);
        AGnssStatusValue status ALIGNED(1);
        guint8 ipV6Addr[16] ALIGNED(1);
} ALIGNED(1) AGnssStatusIpV6;

G_STATIC_ASSERT(sizeof(AGnssStatusIpV6) == 18);

enum GnssFunctions {
        GNSS_SET_CALLBACK = 1,
        GNSS_START = 2,
        GNSS_STOP = 3,
        GNSS_CLEANUP = 4,
        GNSS_INJECT_TIME = 5,
        GNSS_INJECT_LOCATION = 6,
        GNSS_DELETE_AIDING_DATA = 7,
        GNSS_SET_POSITION_MODE = 8,
        GNSS_GET_EXTENSION_AGNSS_RIL = 9,
        GNSS_GET_EXTENSION_GNSS_GEOFENCING = 10,
        GNSS_GET_EXTENSION_AGNSS = 11,
        GNSS_GET_EXTENSION_GNSS_NI = 12,
        GNSS_GET_EXTENSION_GNSS_MEASUREMENT = 13,
        GNSS_GET_EXTENSION_GNSS_NAVIGATION_MESSAGE = 14,
        GNSS_GET_EXTENSION_XTRA = 15,
        GNSS_GET_EXTENSION_GNSS_CONFIGURATION = 16,
        GNSS_GET_EXTENSION_GNSS_DEBUG = 17,
        GNSS_GET_EXTENSION_GNSS_BATCHING = 18
};

enum GnssCallbacks {
        GNSS_LOCATION_CB = 1,
        GNSS_STATUS_CB = 2,
        GNSS_SV_STATUS_CB = 3,
        GNSS_NMEA_CB = 4,
        GNSS_SET_CAPABILITIES_CB = 5,
        GNSS_ACQUIRE_WAKELOCK_CB = 6,
        GNSS_RELEASE_WAKELOCK_CB = 7,
        GNSS_REQUEST_TIME_CB = 8,
        GNSS_SET_SYSTEM_INFO_CB = 9
};

enum GnssDebugFunctions {
        GNSS_DEBUG_GET_DEBUG_DATA = 1
};

enum GnssNiFunctions {
        GNSS_NI_SET_CALLBACK = 1,
        GNSS_NI_RESPOND = 2
};

enum GnssNiCallbacks {
        GNSS_NI_NOTIFY_CB = 1
};

enum GnssXtraFunctions {
        GNSS_XTRA_SET_CALLBACK = 1,
        GNSS_XTRA_INJECT_XTRA_DATA = 2
};

enum GnssXtraCallbacks {
        GNSS_XTRA_DOWNLOAD_REQUEST_CB = 1
};

enum AGnssFunctions {
        AGNSS_SET_CALLBACK = 1,
        AGNSS_DATA_CONN_CLOSED = 2,
        AGNSS_DATA_CONN_FAILED = 3,
        AGNSS_SET_SERVER = 4,
        AGNSS_DATA_CONN_OPEN = 5
};

enum AGnssCallbacks {
        AGNSS_STATUS_IP_V4_CB = 1,
        AGNSS_STATUS_IP_V6_CB = 2,
        AGNSS_STATUS_CB = 3
};

enum AGnssRilFunctions {
        AGNSS_RIL_SET_CALLBACK = 1,
        AGNSS_RIL_SET_REF_LOCATION = 2,
        AGNSS_RIL_SET_SET_ID = 3,
        AGNSS_RIL_UPDATE_NETWORK_STATE = 4,
        AGNSS_RIL_UPDATE_NETWORK_AVAILABILITY = 5
};

enum AGnssRilCallbacks {
        AGNSS_RIL_REQUEST_SET_ID_CB = 1,
        AGNSS_RIL_REQUEST_REF_LOC_CB = 2
};

enum BinderApnIpTypeEnum {
        BINDER_APN_IP_INVALID  = 0,
        BINDER_APN_IP_IPV4     = 1,
        BINDER_APN_IP_IPV6     = 2,
        BINDER_APN_IP_IPV4V6   = 3
};

enum GnssFunctions_1_1 {
        GNSS_SET_CALLBACK_1_1 = 19,
        GNNS_SET_POSITION_MODE_1_1 = 20,
        GNSS_GET_EXTENSION_GNSS_CONFIGURATION_1_1 = 21,
        GNSS_GET_EXTENSION_GNSS_MEASUREMENT_1_1 = 22,
        GNSS_INJECT_BEST_LOCATION = 23
};

enum GnssCallbacks_1_1 {
        GNSS_NAME_CB = 10,
        GNSS_REQUEST_LOCATION_CB = 11
};

enum GnssFunctions_2_0 {
        GNSS_SET_CALLBACK_2_0 = 24,
        GNSS_GET_EXTENSION_GNSS_CONFIGURATION_2_0 = 25,
        GNSS_GET_EXTENSION_GNSS_DEBUG_2_0 = 26,
        GNSS_GET_EXTENSION_AGNSS_2_0 = 27,
        GNSS_GET_EXTENSION_AGNSS_RIL_2_0 = 28,
        GNSS_GET_EXTENSION_GNSS_MEASUREMENTS_2_0 = 29,
        GNSS_GET_EXTENSION_GNSS_MEASUREMENT_CORRECTIONS_2_0 = 29,
        GNSS_GET_EXTENSION_VISIBILITY_CONTROL = 30,
        GNSS_GET_EXTENSION_GNSS_BATCHING_2_0 = 31,
        GNSS_INJECT_BEST_LOCATION_2_0 = 32
};

enum GnssCallbacks_2_0 {
        GNSS_SET_CAPABILITIES_CB_2_0 = 12,
        GNSS_LOCATION_CB_2_0 = 13,
        GNSS_REQUEST_LOCATION_CB_2_0 = 14,
        GNSS_SV_STATUS_CB_2_0 = 15
};

#define GNSS_IFACE(x)       "android.hardware.gnss@1.0::" x
#define GNSS_REMOTE         GNSS_IFACE ("IGnss")
#define GNSS_CALLBACK       GNSS_IFACE ("IGnssCallback")
#define GNSS_DEBUG_REMOTE   GNSS_IFACE ("IGnssDebug")
#define GNSS_NI_REMOTE      GNSS_IFACE ("IGnssNi")
#define GNSS_NI_CALLBACK    GNSS_IFACE ("IGnssNiCallback")
#define GNSS_XTRA_REMOTE    GNSS_IFACE ("IGnssXtra")
#define GNSS_XTRA_CALLBACK  GNSS_IFACE ("IGnssXtraCallback")
#define AGNSS_REMOTE        GNSS_IFACE ("IAGnss")
#define AGNSS_CALLBACK      GNSS_IFACE ("IAGnssCallback")
#define AGNSS_RIL_REMOTE    GNSS_IFACE ("IAGnssRil")
#define AGNSS_RIL_CALLBACK  GNSS_IFACE ("IAGnssRilCallback")

#define GNSS_IFACE_2_0(x)       "android.hardware.gnss@2.0::" x
#define GNSS_REMOTE_2_0         GNSS_IFACE_2_0 ("IGnss")
#define GNSS_CALLBACK_2_0       GNSS_IFACE_2_0 ("IGnssCallback")
#define AGNSS_REMOTE_2_0        GNSS_IFACE_2_0 ("IAGnss")
#define AGNSS_CALLBACK_2_0      GNSS_IFACE_2_0 ("IAGnssCallback")
#define AGNSS_RIL_REMOTE_2_0    GNSS_IFACE_2_0 ("IAGnssRil")
#define AGNSS_RIL_CALLBACK_2_0  GNSS_IFACE_2_0 ("IAGnssRilCallback")

#define NTP_TIMESTAMP_DELTA 2208988800ull

G_END_DECLS

#endif /* GCLUE_BINDER_TYPES_H */
