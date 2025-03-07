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

#include <stdbool.h>
#include <netdb.h>

#include "gclue-binder.h"
#include "gclue-binder-types.h"
#include "gclue-config.h"

const double MpsToKnots = 1.943844;

struct _GClueBinderPrivate {
        gulong m_death_id;
        char *m_fqname;
        char *m_fqname_2_0;
        GBinderServiceManager *m_sm;

        GBinderClient *m_client_gnss;
        GBinderClient *m_client_gnss_2_0;

        GBinderRemoteObject *m_remote_gnss;
        GBinderLocalObject *m_callback_gnss;
        GBinderRemoteObject *m_remote_gnss_2_0;

        GBinderClient *m_client_gnssDebug;
        GBinderRemoteObject *m_remote_gnssDebug;

        GBinderClient *m_client_gnssNi;
        GBinderRemoteObject *m_remote_gnssNi;
        GBinderLocalObject *m_callback_gnssNi;

        GBinderClient *m_client_gnssXtra;
        GBinderRemoteObject *m_remote_gnssXtra;
        GBinderLocalObject *m_callback_gnssXtra;

        GBinderClient *m_client_agnss;
        GBinderRemoteObject *m_remote_agnss;
        GBinderLocalObject *m_callback_agnss;

        GBinderClient *m_client_agnssRil;
        GBinderRemoteObject *m_remote_agnssRil;
        GBinderLocalObject *m_callback_agnssRil;

        int m_gnss2_available;
};

G_DEFINE_TYPE_WITH_CODE(GClueBinder, gclue_binder, G_TYPE_OBJECT,
                        G_ADD_PRIVATE(GClueBinder))

enum {
        SET_LOCATION,
        SIGNAL_LAST
};

static guint signals[SIGNAL_LAST];

gboolean gclue_binder_aGnssSetServer (GClueBinder *binder,
                                      BinderAGnssType type,
                                      const char *hostname,
                                      int port);

gboolean gclue_binder_gnssInjectTime (GClueBinder *binder,
                                      BinderGnssUtcTime timeMs,
                                      int64_t timeReferenceMs,
                                      int32_t uncertaintyMs);

void gclue_binder_dropGnss (GClueBinder *binder);

typedef struct {
        uint16_t seconds;
        uint16_t fraction;
} NtpShort;

typedef struct {
        uint32_t seconds;
        uint32_t fraction;
} NtpTime;

typedef struct {
        uint8_t flags;
        uint8_t stratum;
        int8_t poll;
        int8_t precision;
        NtpShort rootDelay;
        NtpShort rootDispersion;
        uint32_t referenceId;
        NtpTime referenceTimestamp;
        NtpTime originTimestamp;
        NtpTime receiveTimestamp;
        NtpTime transmitTimestamp;
} NtpMessage;

bool
service_exists (GBinderServiceManager *sm,
                const char            *service)
{
        GBinderRemoteObject *obj = gbinder_servicemanager_get_service_sync (sm, service, NULL);

        if (obj)
                return true;
        else
                return false;

        gbinder_remote_object_unref (obj);
        obj = NULL;
}

BinderApnIpType
protocol_to_apn_type (const char* protocol)
{
        if (strcmp (protocol, "ip") == 0)
                return BINDER_APN_IP_IPV4;
        else if (strcmp (protocol, "ipv6") == 0)
                return BINDER_APN_IP_IPV6;
        else if (strcmp (protocol, "dual") == 0)
                return BINDER_APN_IP_IPV4V6;
        else
                return BINDER_APN_IP_INVALID;
}

gboolean
parse_supl_string (const char *supl,
                   char      **domain,
                   int        *port)
{
        if (!supl)
                return FALSE;

        if (supl[0] == '"' && supl[strlen (supl) - 1] == '"') {
                char *cleaned_supl = strdup (supl + 1);
                cleaned_supl[strlen (cleaned_supl) - 1] = '\0';
                supl = cleaned_supl;
        } else
                supl = strdup (supl);

        char *colon = strchr(supl, ':');
        if (!colon)
                return FALSE;

        if (colon == supl)
                return FALSE;

        if (*(colon + 1) == '\0')
                return FALSE;

        *domain = g_strndup(supl, colon - supl);
        if (!*domain)
                return FALSE;

        *port = atoi(colon + 1);
        if (*port == 0 && strcmp(colon + 1, "0") != 0) {
                g_free(*domain);
                *domain = NULL;
                return FALSE;
        }

        return TRUE;
}

int
query_ntp_server (int64_t    *timeMs,
                  int        *uncertaintyMs,
                  int64_t    *timeReferenceMs,
                  const char *ntpserver)
{
        if (ntpserver[0] == '"' && ntpserver[strlen (ntpserver) - 1] == '"') {
                char *cleaned_ntpserver = strdup (ntpserver + 1);
                cleaned_ntpserver[strlen (cleaned_ntpserver) - 1] = '\0';
                ntpserver = cleaned_ntpserver;
        } else
                ntpserver = strdup (ntpserver);

        int sockfd = socket (AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
                return 0;

        struct timeval timeout;
        // timeout after 3 seconds
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &timeout, sizeof (timeout)) < 0) {
                close (sockfd);
                return 0;
        }

        struct hostent *server = gethostbyname (ntpserver);
        if (server == NULL) {
                close (sockfd);
                return 0;
        }

        struct sockaddr_in servaddr;
        memset (&servaddr, 0, sizeof (servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons (123);
        memcpy (&servaddr.sin_addr.s_addr, server->h_addr, server->h_length);

        NtpMessage request;
        memset (&request, 0, sizeof (NtpMessage));
        request.flags = 0x1B;

        struct timeval currentTime;
        gettimeofday (&currentTime, NULL);
        request.transmitTimestamp.seconds = htonl (currentTime.tv_sec + NTP_TIMESTAMP_DELTA);
        request.transmitTimestamp.fraction = htonl ((uint32_t) ((double) (currentTime.tv_usec + 1) * (double) (1LL << 32) / 1000000));
        int64_t requestTicks = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;

        sendto (sockfd, (const char *) &request, sizeof (NtpMessage), 0,
               (const struct sockaddr *) &servaddr, sizeof (servaddr));

        NtpMessage response;
        socklen_t len = sizeof (servaddr);
        int n = recvfrom (sockfd, (char *) &response, sizeof (NtpMessage),
                         MSG_WAITALL, (struct sockaddr *) &servaddr, &len);

        struct timeval receiveTime;
        gettimeofday (&receiveTime, NULL);
        int64_t responseTicks = receiveTime.tv_sec * 1000 + receiveTime.tv_usec / 1000;

        if (n < 0) {
                close (sockfd);
                return 0;
        }

        int64_t secs = (int64_t) ntohl (response.transmitTimestamp.seconds) - NTP_TIMESTAMP_DELTA;
        *timeMs = secs * 1000 + ((int64_t) ntohl (response.transmitTimestamp.fraction) * 1000) / (1LL << 32);
        *timeReferenceMs = responseTicks;
        *uncertaintyMs = abs((int) ((responseTicks - requestTicks) / 2));

        close(sockfd);
        return 1;
}

static const char *
get_ntp_server_config ()
{
        GClueConfig *config;

        config = gclue_config_get_singleton ();
        return gclue_config_get_binder_ntp_server (config);
}

static const char *
get_supl_server_config ()
{
        GClueConfig *config;

        config = gclue_config_get_singleton ();
        if (!gclue_config_get_binder_supl_enabled (config))
                return NULL;

        return gclue_config_get_binder_supl_server (config);
}

const void *
geoclue_binder_gnss_decode_struct1 (GBinderReader *in,
                                    guint          size)
{
        const void *result = NULL;
        GBinderBuffer *buf = gbinder_reader_read_buffer (in);

        if (buf && buf->size == size)
                result = buf->data;

        gbinder_buffer_free (buf);
        return result;
}

#define geoclue_binder_gnss_decode_struct(type,in) \
        ((const type*)geoclue_binder_gnss_decode_struct1(in, sizeof(type)))

gboolean
nmea_checksum_valid (GString *nmea)
{
        unsigned char checksum = 0;
        for (int i = 1; i < nmea->len; ++i) {
                if (nmea->str[i] == '*') {
                        if (nmea->len < i+3)
                                return FALSE;

                        checksum ^= g_ascii_strtoll (g_string_new_len (nmea->str + i + 1, 2)->str, NULL, 16);

                        break;
                }

                checksum ^= nmea->str[i];
        }

        return checksum == 0;
}

void
parse_rmc (GString *nmea)
{
        gchar **fields = g_strsplit (nmea->str, ",", 0);
        if (g_strv_length (fields) < 12)
                return;

        if (fields[10]) {
                double variation = g_strtod (fields[10], NULL);
                if (fields[11][0] == 'W')
                        variation = -variation;
        }
}

void
process_nmea (gint64      timestamp,
              const char *nmea_data)
{
        GString *nmea;
        int length = strlen (nmea_data);
        while (length > 0 && g_ascii_isspace (nmea_data[length - 1]))
                --length;

        if (length == 0)
                return;

        nmea = g_string_new_len (nmea_data, length);

        g_debug("binder: NMEA timestamp %s", nmea_data);

        if (!nmea_checksum_valid (nmea))
                return;

        // truncate checksum and * from end of sentence
        nmea = g_string_truncate (nmea, nmea->len);

        if (g_str_has_prefix (nmea->str, "$GPRMC"))
                parse_rmc (nmea);
}


GBinderLocalReply *
gclue_binder_gnss_cb (GBinderLocalObject   *obj,
                      GBinderRemoteRequest *req,
                      guint                 code,
                      guint                 flags,
                      int                  *status,
                      void                 *user_data)
{
        const char *iface = gbinder_remote_request_interface (req);
        GClueBinder *hbinder = (GClueBinder *) user_data;

        if (!g_strcmp0 (iface, GNSS_CALLBACK)) {
                GBinderReader reader;

                gbinder_remote_request_init_reader (req, &reader);
                switch (code) {
                case GNSS_LOCATION_CB:
                        g_debug ("binder: GNSS location");
                        GClueBinderLocation* loc = g_slice_new0 (GClueBinderLocation);

                        const GnssLocation *location = geoclue_binder_gnss_decode_struct (GnssLocation, &reader);

                        loc->timestamp = location->timestamp;
                        g_debug ("binder: Location timestamp: %" G_GUINT64_FORMAT, loc->timestamp);

                        if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_LAT_LONG) {
                                loc->latitude = location->latitudeDegrees;
                                loc->longitude = location->longitudeDegrees;
                                g_debug ("binder: Latitude: %f, Longitude: %f", loc->latitude, loc->longitude);
                        }

                        if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_ALTITUDE) {
                                loc->altitude = location->altitudeMeters;
                                g_debug ("binder: Altitude: %f meters", loc->altitude);
                        }

                        if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_SPEED) {
                                loc->speed = location->speedMetersPerSec * MpsToKnots;
                                g_debug ("binder: Speed: %f knots", loc->speed);
                        }

                        if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_BEARING) {
                                loc->direction = location->bearingDegrees;
                                g_debug ("binder: Bearing: %f degrees", loc->direction);
                        }

                        if ((location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_HORIZONTAL_ACCURACY) ||
                            (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_VERTICAL_ACCURACY)) {
                                GClueBinderAccuracy* accuracy = g_slice_new0 (GClueBinderAccuracy);
                                if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_HORIZONTAL_ACCURACY) {
                                        accuracy->horizontal = location->horizontalAccuracyMeters;
                                        g_debug ("binder: Horizontal Accuracy: %f meters", accuracy->horizontal);
                                }
                                if (location->gnssLocationFlags & BINDER_GNSS_LOCATION_HAS_VERTICAL_ACCURACY) {
                                        accuracy->vertical = location->verticalAccuracyMeters;
                                        g_debug ("binder: Vertical Accuracy: %f meters", accuracy->vertical);
                                }
                                loc->accuracy = accuracy;
                        }

                        g_signal_emit (hbinder, signals[SET_LOCATION], 0, loc);
                        break;
                case GNSS_STATUS_CB:
                        guint32 stat;
                        if (gbinder_reader_read_uint32 (&reader, &stat)) {
                                if (stat == BINDER_GNSS_STATUS_ENGINE_ON)
                                        g_debug ("binder: GNSS status engine on");
                                if (stat == BINDER_GNSS_STATUS_ENGINE_OFF)
                                        g_debug ("binder: GNSS status engine off");
                                if (stat == BINDER_GNSS_STATUS_SESSION_END)
                                        g_debug ("binder: GNSS status session end");
                                if (stat == BINDER_GNSS_STATUS_SESSION_BEGIN)
                                        g_debug("binder: GNSS status session begin");
                        }
                        break;
                case GNSS_SV_STATUS_CB:
                        const GnssSvStatus *sv_status = geoclue_binder_gnss_decode_struct (GnssSvStatus, &reader);

                        g_debug ("binder: Number of SVs: %u", sv_status->numSvs);

                        GList *satellites = g_list_alloc ();
                        GList *used_prns = g_list_alloc ();

                        for (int i = 0; i < sv_status->numSvs; ++i) {
                                GClueBinderSatelliteInfo *sat_info = g_slice_new0 (GClueBinderSatelliteInfo);
                                GnssSvInfo sv_info = sv_status->gnssSvList[i];

                                g_debug ("binder: SV ID: %d, Constellation: %d, C/N0 dB-Hz: %f, Elevation: %f, Azimuth: %f, Carrier frequency: %f",
                                         sv_info.svid, sv_info.constellation, sv_info.cN0Dbhz, sv_info.elevationDegrees, sv_info.azimuthDegrees, sv_info.carrierFrequencyHz);

                                sat_info->snr = sv_info.cN0Dbhz;
                                sat_info->elevation = sv_info.elevationDegrees;
                                sat_info->azimuth = sv_info.azimuthDegrees;
                                int prn = sv_info.svid;
                                // From https://github.com/barbeau/gpstest
                                // and https://github.com/mvglasow/satstat/wiki/NMEA-IDs
                                if (sv_info.constellation == SBAS) {
                                        g_debug ("binder: SV constellation is SBAS");
                                        prn -= 87;
                                } else if (sv_info.constellation == GLONASS) {
                                        g_debug ("binder: SV constellation is GLONASS");
                                        prn += 64;
                                } else if (sv_info.constellation == BEIDOU) {
                                        g_debug ("binder: SV constellation is BEIDOU");
                                        prn += 200;
                                } else if (sv_info.constellation == GALILEO) {
                                        g_debug ("binder: SV constellation is GALILEO");
                                        prn += 300;
                                } else if (sv_info.constellation == GPS)
                                        g_debug ("binder: SV constellation is GPS");
                                else if (sv_info.constellation == QZSS)
                                        g_debug ("binder: SV constellation is QZSS");

                                sat_info->prn = prn;
                                satellites = g_list_append (satellites, sat_info);

                                g_debug ("binder: Adjusted PRN: %d", prn);

                                if (sv_info.svFlag & BINDER_GNSS_SV_FLAGS_USED_IN_FIX) {
                                        used_prns = g_list_append (used_prns, &prn);
                                        g_debug ("binder: SV %d used in fix", sv_info.svid);
                                } else if (sv_info.svFlag & BINDER_GNSS_SV_FLAGS_NONE)
                                        g_debug("binder: SV %d has no flags", sv_info.svid);
                                else if (sv_info.svFlag & BINDER_GNSS_SV_FLAGS_HAS_EPHEMERIS_DATA)
                                        g_debug("binder: SV %d has ephemeris data", sv_info.svid);
                                else if (sv_info.svFlag & BINDER_GNSS_SV_FLAGS_HAS_ALMANAC_DATA)
                                        g_debug("binder: SV %d has almanac data", sv_info.svid);
                                else if (sv_info.svFlag & BINDER_GNSS_SV_FLAGS_HAS_CARRIER_FREQUENCY)
                                        g_debug("binder: SV %d has carrier frequency", sv_info.svid);
                        }
                        break;
                case GNSS_NMEA_CB:
                        gint64 timestamp;
                        if (gbinder_reader_read_int64 (&reader, &timestamp)) {
                                char *nmea_data = gbinder_reader_read_hidl_string (&reader);
                                if (nmea_data) {
                                        process_nmea (timestamp, nmea_data);
                                        g_free (nmea_data);
                                }
                        }
                        break;
                case GNSS_SET_CAPABILITIES_CB:
                        guint32 capabilities;
                        if (gbinder_reader_read_uint32 (&reader, &capabilities)) {
                                g_debug ("binder: capabilities:");
                                if (capabilities & SCHEDULING)
                                        g_debug ("  - SCHEDULING");
                                if (capabilities & MSB)
                                        g_debug ("  - MSB");
                                if (capabilities & MSA)
                                        g_debug ("  - MSA");
                                if (capabilities & SINGLE_SHOT)
                                        g_debug ("  - SINGLE_SHOT");
                                if (capabilities & ON_DEMAND_TIME)
                                        g_debug ("  - ON_DEMAND_TIME");
                                if (capabilities & GEOFENCING)
                                        g_debug ("  - GEOFENCING");
                                if (capabilities & MEASUREMENTS)
                                        g_debug ("  - MEASUREMENTS");
                                if (capabilities & NAV_MESSAGES)
                                        g_debug ("  - NAV_MESSAGES");
                        }
                        break;
                case GNSS_ACQUIRE_WAKELOCK_CB:
                case GNSS_RELEASE_WAKELOCK_CB:
                        break;
                case GNSS_REQUEST_TIME_CB:
                        g_debug ("binder: GNSS request UTC time");
                        break;
                case GNSS_SET_SYSTEM_INFO_CB:
                        guint16 year_of_hw;
                        if (gbinder_reader_read_uint16 (&reader, &year_of_hw))
                                g_debug ("binder: GNSS set system info year %d", year_of_hw);
                        break;
                default:
                        g_debug ("Failed to decode GNSS callback %u", code);
                        break;
                }
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32 (gbinder_local_object_new_reply (obj), 0);
        } else {
                g_debug ("Unknown interface %s and code %u", iface, code);
                *status = GBINDER_STATUS_FAILED;
        }
        return NULL;
}

GBinderLocalReply *
gclue_binder_gnss_xtra_cb (GBinderLocalObject   *obj,
                           GBinderRemoteRequest *req,
                           guint                 code,
                           guint                 flags,
                           int                  *status,
                           void                 *user_data)
{
        const char *iface = gbinder_remote_request_interface (req);

        if (!g_strcmp0 (iface, GNSS_XTRA_CALLBACK)) {
                GBinderReader reader;

                gbinder_remote_request_init_reader (req, &reader);
                switch (code) {
                case GNSS_XTRA_DOWNLOAD_REQUEST_CB:
                        g_debug ("binder: XTRA download request");
                        break;
                default:
                        g_debug ("Failed to decode GNSS XTRA callback %u", code);
                        break;
                }
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32 (gbinder_local_object_new_reply (obj), 0);
        } else {
                g_debug ("Unknown interface %s and code %u", iface, code);
                *status = GBINDER_STATUS_FAILED;
        }
        return NULL;
}

GBinderLocalReply *
gclue_binder_agnss_cb (GBinderLocalObject   *obj,
                       GBinderRemoteRequest *req,
                       guint                 code,
                       guint                 flags,
                       int                  *status,
                       void                 *user_data)
{
        const char *iface = gbinder_remote_request_interface (req);
        if (!g_strcmp0 (iface, AGNSS_CALLBACK)) {
                GBinderReader reader;

                gbinder_remote_request_init_reader (req, &reader);
                switch (code) {
                case AGNSS_STATUS_IP_V4_CB:
                        gint32 ipv4;

                        const AGnssStatusIpV4 *v4status = geoclue_binder_gnss_decode_struct (AGnssStatusIpV4, &reader);

                        ipv4 = v4status->ipV4Addr;
                        g_debug ("binder: AGNSS IPv4 %d", ipv4);

                        if (v4status->type & TYPE_SUPL)
                                g_debug ("binder: AGNSS type is SUPL");
                        if (v4status->type & TYPE_C2K)
                                g_debug ("binder: AGNSS type is C2K");
                        if (v4status->type & TYPE_SUPL_EIMS)
                                g_debug ("binder: AGNSS type is SUPL EIMS");
                        if (v4status->type & TYPE_SUPL_IMS)
                                g_debug ("binder: AGNSS type is SUPL IMS");
                        if (v4status->status & REQUEST_AGNSS_DATA_CONN)
                                g_debug ("binder: AGNSS request data conn");
                        if (v4status->status & RELEASE_AGNSS_DATA_CONN)
                                g_debug ("binder: AGNSS release data conn");
                        if (v4status->status & AGNSS_STATUS_DATA_CONNECTED)
                                g_debug ("binder: AGNSS data connected");
                        if (v4status->status & AGNSS_STATUS_DATA_CONN_DONE)
                                g_debug ("binder: AGNSS data conn done");
                        if (v4status->status & AGNSS_STATUS_DATA_CONN_FAILED)
                                g_debug ("binder: AGNSS data conn failed");
                        break;
                case AGNSS_STATUS_IP_V6_CB:
                        const AGnssStatusIpV6 *v6status = geoclue_binder_gnss_decode_struct (AGnssStatusIpV6, &reader);

                        if (v6status->type & TYPE_SUPL)
                                g_debug ("binder: AGNSS type is SUPL");
                        if (v6status->type & TYPE_C2K)
                                g_debug ("binder: AGNSS type is C2K");
                        if (v6status->type & TYPE_SUPL_EIMS)
                                g_debug ("binder: AGNSS type is SUPL EIMS");
                        if (v6status->type & TYPE_SUPL_IMS)
                                g_debug ("binder: AGNSS type is SUPL IMS");
                        if (v6status->status & REQUEST_AGNSS_DATA_CONN)
                                g_debug ("binder: AGNSS request data conn");
                        if (v6status->status & RELEASE_AGNSS_DATA_CONN)
                                g_debug ("binder: AGNSS release data conn");
                        if (v6status->status & AGNSS_STATUS_DATA_CONNECTED)
                                g_debug ("binder: AGNSS data connected");
                        if (v6status->status & AGNSS_STATUS_DATA_CONN_DONE)
                                g_debug ("binder: AGNSS data conn done");
                        if (v6status->status & AGNSS_STATUS_DATA_CONN_FAILED)
                                g_debug ("binder: AGNSS data conn failed");
                        break;
                default:
                        g_debug ("Failed to decode AGNSS callback %u", code);
                        break;
                }
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32 (gbinder_local_object_new_reply (obj), 0);
        } else {
                g_debug ("Unknown interface %s and code %u", iface, code);
                *status = GBINDER_STATUS_FAILED;
        }
        return NULL;
}


GBinderLocalReply *
gclue_binder_agnss_ril_cb (GBinderLocalObject   *obj,
                           GBinderRemoteRequest *req,
                           guint                 code,
                           guint                 flags,
                           int                  *status,
                           void                 *user_data)
{
        const char *iface = gbinder_remote_request_interface (req);

        if (!g_strcmp0 (iface, AGNSS_RIL_CALLBACK)) {
                GBinderReader reader;

                gbinder_remote_request_init_reader (req, &reader);
                switch (code) {
                case AGNSS_RIL_REQUEST_SET_ID_CB:
                        guint32 id;
                        if (gbinder_reader_read_uint32 (&reader, &id)) {
                                switch (id) {
                                case IMSI:
                                        g_debug ("binder: AGNSS RIL request set ID IMSI");
                                        break;
                                case MSISDN:
                                        g_debug ("binder: AGNSS RIL request set ID MSISDN");
                                        break;
                                default:
                                        g_debug ("binder: AGNSS RIL request set unknown ID %d", id);
                                        break;
                                }
                        }
                        break;
                case AGNSS_RIL_REQUEST_REF_LOC_CB:
                        g_debug ("binder: AGNSS RIL request ref location");
                        break;
                default:
                        g_debug ("Failed to decode AGNSS RIL callback %u", code);
                        break;
                }
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32 (gbinder_local_object_new_reply(obj), 0);
        } else {
                g_debug ("Unknown interface %s and code %u", iface, code);
                *status = GBINDER_STATUS_FAILED;
        }
        return NULL;
}


GBinderLocalReply *
gclue_binder_gnss_ni_cb (GBinderLocalObject *obj,
                         GBinderRemoteRequest *req,
                         guint code,
                         guint flags,
                         int *status,
                         void *user_data)
{
        const char *iface = gbinder_remote_request_interface (req);

        if (!g_strcmp0 (iface, GNSS_NI_CALLBACK)) {
                GBinderReader reader;

                gbinder_remote_request_init_reader (req, &reader);
                switch (code) {
                case GNSS_NI_NOTIFY_CB:
                        g_debug ("binder: GNSS NI notify");
                        break;
                default:
                        g_debug ("Failed to decode GNSS NI callback %u", code);
                        break;
                }
                *status = GBINDER_STATUS_OK;
                return gbinder_local_reply_append_int32 (gbinder_local_object_new_reply (obj), 0);
        } else {
                g_debug ("Unknown interface %s and code %u", iface, code);
                *status = GBINDER_STATUS_FAILED;
        }
        return NULL;
}

void
gclue_binder_gnss_died_cb (GBinderRemoteObject *obj,
                           void                *user_data)
{
        GClueBinder *hbinder = (GClueBinder *) user_data;
        gclue_binder_dropGnss (hbinder);
}

/*==========================================================================*
 * Backend class
 *==========================================================================*/

static void
gclue_binder_class_init (GClueBinderClass *klass)
{
        signals[SET_LOCATION] = g_signal_lookup ("setLocation", GCLUE_TYPE_BINDER);
}

void
gclue_binder_dropGnss (GClueBinder *hbinder)
{
        GClueBinderPrivate *priv = hbinder->priv;

        if (priv->m_callback_gnss) {
                gbinder_local_object_drop (priv->m_callback_gnss);
                priv->m_callback_gnss = NULL;
        }
        if (priv->m_client_gnss) {
                gbinder_client_unref (priv->m_client_gnss);
                priv->m_client_gnss = NULL;

                if (priv->m_client_gnss_2_0) {
                        gbinder_client_unref (priv->m_client_gnss_2_0);
                        priv->m_client_gnss_2_0 = NULL;
                }
        }
        if (priv->m_remote_gnss) {
                gbinder_remote_object_remove_handler (priv->m_remote_gnss, priv->m_death_id);
                gbinder_remote_object_unref (priv->m_remote_gnss);
                priv->m_death_id = 0;
                priv->m_remote_gnss = NULL;
        }
        if (priv->m_client_gnssDebug) {
                gbinder_client_unref (priv->m_client_gnssDebug);
                priv->m_client_gnssDebug = NULL;
        }
        if (priv->m_remote_gnssDebug) {
                gbinder_remote_object_unref (priv->m_remote_gnssDebug);
                priv->m_remote_gnssDebug = NULL;
        }
        if (priv->m_callback_gnssNi) {
                gbinder_local_object_drop (priv->m_callback_gnssNi);
                priv->m_callback_gnssNi = NULL;
        }
        if (priv->m_client_gnssNi) {
                gbinder_client_unref (priv->m_client_gnssNi);
                priv->m_client_gnssNi = NULL;
        }
        if (priv->m_remote_gnssNi) {
                gbinder_remote_object_unref (priv->m_remote_gnssNi);
                priv->m_remote_gnssNi = NULL;
        }
        if (priv->m_callback_gnssXtra) {
                gbinder_local_object_drop (priv->m_callback_gnssXtra);
                priv->m_callback_gnssXtra = NULL;
        }
        if (priv->m_client_gnssXtra) {
                gbinder_client_unref (priv->m_client_gnssXtra);
                priv->m_client_gnssXtra = NULL;
        }
        if (priv->m_remote_gnssXtra) {
                gbinder_remote_object_unref (priv->m_remote_gnssXtra);
                priv->m_remote_gnssXtra = NULL;
        }
        if (priv->m_callback_agnss) {
                gbinder_local_object_drop (priv->m_callback_agnss);
                priv->m_callback_agnss = NULL;
        }
        if (priv->m_client_agnss) {
                gbinder_client_unref (priv->m_client_agnss);
                priv->m_client_agnss = NULL;
        }
        if (priv->m_remote_agnss) {
                gbinder_remote_object_unref (priv->m_remote_agnss);
                priv->m_remote_agnss = NULL;
        }
        if (priv->m_callback_agnssRil) {
                gbinder_local_object_drop (priv->m_callback_agnssRil);
                priv->m_callback_agnssRil = NULL;
        }
        if (priv->m_client_agnssRil) {
                gbinder_client_unref (priv->m_client_agnssRil);
                priv->m_client_agnssRil = NULL;
        }
        if (priv->m_remote_agnssRil) {
                gbinder_remote_object_unref (priv->m_remote_agnssRil);
                priv->m_remote_agnssRil = NULL;
        }
        if (priv->m_sm) {
                gbinder_servicemanager_unref (priv->m_sm);
                priv->m_sm = NULL;
        }

        g_free (priv->m_fqname);
        priv->m_fqname = NULL;

        g_free (priv->m_fqname_2_0);
        priv->m_fqname_2_0 = NULL;
}

static
gboolean is_reply_success (GBinderRemoteReply *reply)
{
        GBinderReader reader;
        gint32 status;
        gboolean result;
        gbinder_remote_reply_init_reader (reply, &reader);

        if (!gbinder_reader_read_int32 (&reader, &status) || status != 0)
                return FALSE;

        if (!gbinder_reader_read_bool (&reader, &result) || !result)
                return FALSE;

        return TRUE;
}

static
GBinderRemoteObject* get_extension_object (GBinderRemoteReply *reply)
{
        GBinderReader reader;
        gint32 status;
        gbinder_remote_reply_init_reader (reply, &reader);

        if (!gbinder_reader_read_int32 (&reader, &status) || status != 0) {
                g_debug ("Failed to get extension object %d", status);
                return NULL;
        }

        return gbinder_reader_read_object (&reader);
}

static void
gclue_binder_init (GClueBinder *hbinder)
{
        hbinder->priv = gclue_binder_get_instance_private (hbinder);
}

static void
on_binder_destroyed (gpointer data,
                     GObject *where_the_object_was)
{
        GClueBinder **hbinder = (GClueBinder **) data;

        gclue_binder_dropGnss (*hbinder);

        *hbinder = NULL;
}

GClueBinder*
gclue_binder_get_singleton (void)
{
        static GClueBinder *hbinder = NULL;

        if (hbinder == NULL) {
                hbinder = g_object_new (GCLUE_TYPE_BINDER, NULL);
                g_object_weak_ref (G_OBJECT (hbinder),
                                   on_binder_destroyed,
                                   &hbinder);
        } else
                g_object_ref (hbinder);

        return GCLUE_BINDER (hbinder);
}

gboolean
gclue_binder_gnssInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;
        gboolean ntp_ret = FALSE;
        int64_t timeMs, timeReferenceMs;
        int32_t uncertaintyMs;
        const char *ntp;

        g_debug ("Initialising GNSS interface");

        priv->m_sm = gbinder_servicemanager_new (GBINDER_DEFAULT_HWBINDER);
        if (priv->m_sm) {
                int status = 0;

                /* Fetch remote reference from hwservicemanager */
                priv->m_fqname = g_strconcat (GNSS_REMOTE "/default", NULL);
                priv->m_fqname_2_0 = g_strconcat (GNSS_REMOTE_2_0 "/default", NULL);

                priv->m_remote_gnss = gbinder_servicemanager_get_service_sync (priv->m_sm,
                                                                              priv->m_fqname, &status);

                if (service_exists (priv->m_sm, priv->m_fqname_2_0)) {
                        g_debug ("Service %s exists", priv->m_fqname_2_0);
                        priv->m_gnss2_available = 1;

                        priv->m_remote_gnss_2_0 = gbinder_servicemanager_get_service_sync (priv->m_sm,
                                                                                        priv->m_fqname_2_0, NULL);
                } else {
                        g_debug ("Service %s does not exist", priv->m_fqname_2_0);
                        priv->m_gnss2_available = 0;
                }

                if (priv->m_remote_gnss) {
                        GBinderLocalRequest *req;
                        GBinderRemoteReply *reply;

                        /* get_service returns auto-released reference,
                         * we need to add a reference of our own */
                        gbinder_remote_object_ref (priv->m_remote_gnss);
                        priv->m_client_gnss = gbinder_client_new (priv->m_remote_gnss, GNSS_REMOTE);
                        priv->m_death_id = gbinder_remote_object_add_death_handler (priv->m_remote_gnss, gclue_binder_gnss_died_cb, binder);
                        priv->m_callback_gnss = gbinder_servicemanager_new_local_object (priv->m_sm, GNSS_CALLBACK, gclue_binder_gnss_cb, binder);

                        /* IGnss::setCallback */
                        req = gbinder_client_new_request (priv->m_client_gnss);
                        gbinder_local_request_append_local_object (req, priv->m_callback_gnss);
                        reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                                    GNSS_SET_CALLBACK, req, &status);

                        if (priv->m_gnss2_available == 1) {
                                if (priv->m_remote_gnss_2_0)
                                        priv->m_client_gnss_2_0 = gbinder_client_new (priv->m_remote_gnss_2_0, GNSS_REMOTE_2_0);
                                else
                                        priv->m_gnss2_available = 1;
                        }

                        ntp = get_ntp_server_config ();
                        int success = query_ntp_server (&timeMs, &uncertaintyMs, &timeReferenceMs, ntp);
                        if (!success)
                                g_debug ("Failed to query NTP server %s", ntp);
                        else {
                                g_debug ("Injecting epoch time %ld from NTP server %s", timeMs, ntp);
                                ntp_ret = gclue_binder_gnssInjectTime (binder, timeMs, timeReferenceMs, uncertaintyMs);
                                if (!ntp_ret)
                                        g_debug ("Failed to inject epoch time into GNSS modem");
                        }

                        if (!status)
                                ret = is_reply_success (reply);

                        gbinder_local_request_unref (req);
                        gbinder_remote_reply_unref (reply);
                }
        }

        if (!ret)
                g_debug ("Failed to initialise GNSS interface");

        return ret;
}

gboolean
gclue_binder_gnssStart (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;

        if (priv->m_client_gnss) {
                int status = 0;
                GBinderRemoteReply *reply;

                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                            GNSS_START, NULL, &status);

                if (!status)
                        ret = is_reply_success (reply);

                gbinder_remote_reply_unref (reply);
        }

        if (!ret)
                g_debug ("Failed to start positioning");

        return ret;
}

gboolean
gclue_binder_gnssStop (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;

        if (priv->m_client_gnss) {
                int status = 0;
                GBinderRemoteReply *reply;

                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                            GNSS_STOP, NULL, &status);

                if (!status)
                        ret = is_reply_success (reply);

                gbinder_remote_reply_unref (reply);
        }

        if (!ret)
                g_debug ("Failed to stop positioning");

        return ret;
}

void
gclue_binder_gnssCleanup (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        if (priv->m_client_gnss)
                gbinder_client_transact (priv->m_client_gnss, GNSS_CLEANUP, 0, NULL, NULL, NULL, NULL);
}

gboolean
gclue_binder_gnssInjectLocation (GClueBinder *binder,
                                 double       latitudeDegrees,
                                 double       longitudeDegrees,
                                 float        accuracyMeters)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;

        if (priv->m_client_gnss) {
                int status = 0;

                GBinderLocalRequest *req;
                GBinderRemoteReply *reply;
                GBinderWriter writer;

                req = gbinder_client_new_request (priv->m_client_gnss);
                gbinder_local_request_init_writer (req, &writer);
                gbinder_writer_append_double (&writer, latitudeDegrees);
                gbinder_writer_append_double (&writer, longitudeDegrees);
                gbinder_writer_append_float (&writer, accuracyMeters);
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                            GNSS_INJECT_LOCATION, req, &status);

                if (!status)
                        ret = is_reply_success (reply);

                if (!ret)
                        g_debug ("Failed to inject location");

                gbinder_local_request_unref (req);
                gbinder_remote_reply_unref (reply);
        }
        return ret;
}

gboolean
gclue_binder_gnssInjectTime (GClueBinder      *binder,
                             BinderGnssUtcTime timeMs,
                             int64_t           timeReferenceMs,
                             int32_t           uncertaintyMs)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;

        if (priv->m_client_gnss) {
                int status = 0;
                GBinderLocalRequest *req;
                GBinderRemoteReply *reply;
                GBinderWriter writer;

                req = gbinder_client_new_request (priv->m_client_gnss);
                gbinder_local_request_init_writer (req, &writer);
                gbinder_writer_append_int64 (&writer, timeMs);
                gbinder_writer_append_int64 (&writer, timeReferenceMs);
                gbinder_writer_append_int32 (&writer, uncertaintyMs);

                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                            GNSS_INJECT_TIME, req, &status);

                if (!status)
                        ret = is_reply_success (reply);

                if (!ret)
                        g_debug ("Failed to inject time");

                gbinder_local_request_unref (req);
                gbinder_remote_reply_unref (reply);
        }
        return ret;
}

void
gclue_binder_gnssDeleteAidingData (GClueBinder         *binder,
                                   BinderGnssAidingData aidingDataFlags)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        if (priv->m_client_gnss) {
                GBinderLocalRequest *req;

                req = gbinder_client_new_request (priv->m_client_gnss);
                gbinder_local_request_append_int32 (req, aidingDataFlags);
                gbinder_client_transact (priv->m_client_gnss, GNSS_DELETE_AIDING_DATA,
                                         0, req, NULL, NULL, NULL);

                gbinder_local_request_unref (req);
        }
}

gboolean
gclue_binder_gnssSetPositionMode (GClueBinder                 *binder,
                                  BinderGnssPositionMode       mode,
                                  BinderGnssPositionRecurrence recurrence,
                                  guint32                      minIntervalMs,
                                  guint32                      preferredAccuracyMeters,
                                  guint32                      preferredTimeMs)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;

        if (priv->m_client_gnss) {
                int status = 0;
                GBinderLocalRequest *req;
                GBinderRemoteReply *reply;
                GBinderWriter writer;

                req = gbinder_client_new_request (priv->m_client_gnss);
                gbinder_local_request_init_writer (req, &writer);
                gbinder_writer_append_int32 (&writer, mode);
                gbinder_writer_append_int32 (&writer, recurrence);
                gbinder_writer_append_int32 (&writer, minIntervalMs);
                gbinder_writer_append_int32 (&writer, preferredAccuracyMeters);
                gbinder_writer_append_int32 (&writer, preferredTimeMs);
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                            GNSS_SET_POSITION_MODE, req, &status);

                if (!status)
                        ret = is_reply_success (reply);

                if (!ret)
                        g_debug ("GNSS set position mode failed");

                gbinder_local_request_unref (req);
                gbinder_remote_reply_unref (reply);
        }
        return ret;
}

void
gclue_binder_gnssDebugInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        GBinderRemoteReply *reply;
        int status = 0;

        reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                    GNSS_GET_EXTENSION_GNSS_DEBUG, NULL, &status);

        if (!status) {
                priv->m_remote_gnssDebug = get_extension_object (reply);
                if (priv->m_remote_gnssDebug) {
                        g_debug ("Initialising GNSS Debug interface");
                        priv->m_client_gnssDebug = gbinder_client_new (priv->m_remote_gnssDebug, GNSS_DEBUG_REMOTE);
                }
        }
        gbinder_remote_reply_unref(reply);
}

void
gclue_binder_gnssNiInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        GBinderRemoteReply *reply;
        int status = 0;

        reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                    GNSS_GET_EXTENSION_GNSS_NI, NULL, &status);

        if (!status) {
                priv->m_remote_gnssNi = get_extension_object(reply);

                if (priv->m_remote_gnssNi) {
                        g_debug ("Initialising GNSS NI interface");
                        GBinderLocalRequest *req;
                        priv->m_client_gnssNi = gbinder_client_new (priv->m_remote_gnssNi, GNSS_NI_REMOTE);
                        priv->m_callback_gnssNi = gbinder_servicemanager_new_local_object (priv->m_sm, GNSS_NI_CALLBACK, gclue_binder_gnss_ni_cb, binder);

                        gbinder_remote_reply_unref (reply);

                        /* IGnssNi::setCallback */
                        req = gbinder_client_new_request (priv->m_client_gnssNi);
                        gbinder_local_request_append_local_object (req, priv->m_callback_gnssNi);
                        reply = gbinder_client_transact_sync_reply (priv->m_client_gnssNi,
                                                                    GNSS_NI_SET_CALLBACK, req, &status);

                        if (!status) {
                                if (!gbinder_remote_reply_read_int32 (reply, &status) || status != 0)
                                        g_debug ("Initialising GNSS NI interface failed %d", status);
                        }

                        gbinder_local_request_unref(req);
                }
        }
        gbinder_remote_reply_unref(reply);
}

void
gclue_binder_gnssNiRespond (GClueBinder               *binder,
                            int32_t                    notifId,
                            BinderGnssUserResponseType userResponse)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        if (priv->m_client_gnssNi) {
                int status = 0;
                GBinderLocalRequest *req;
                GBinderRemoteReply *reply;
                GBinderWriter writer;

                req = gbinder_client_new_request (priv->m_client_gnssNi);
                gbinder_local_request_init_writer (req, &writer);
                gbinder_writer_append_int32 (&writer, notifId);
                gbinder_writer_append_int32 (&writer, userResponse);

                reply = gbinder_client_transact_sync_reply (priv->m_client_gnssNi,
                                                            GNSS_NI_RESPOND, req, &status);

                if (!status) {
                        if (!gbinder_remote_reply_read_int32 (reply, &status) || status != 0)
                                g_debug ("GNSS NI respond failed %d", status);
                }

                gbinder_local_request_unref (req);
                gbinder_remote_reply_unref (reply);
        }
}

void
gclue_binder_gnssXtraInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        GBinderRemoteReply *reply;
        int status = 0;

        reply = gbinder_client_transact_sync_reply (priv->m_client_gnss,
                                                    GNSS_GET_EXTENSION_XTRA, NULL, &status);

        if (!status) {
                priv->m_remote_gnssXtra = get_extension_object (reply);

                if (priv->m_remote_gnssXtra) {
                        g_debug ("Initialising GNSS Xtra interface");
                        GBinderLocalRequest *req;
                        priv->m_client_gnssXtra = gbinder_client_new (priv->m_remote_gnssXtra, GNSS_XTRA_REMOTE);
                        priv->m_callback_gnssXtra = gbinder_servicemanager_new_local_object (priv->m_sm, GNSS_XTRA_CALLBACK, gclue_binder_gnss_xtra_cb, binder);

                        gbinder_remote_reply_unref (reply);

                        /* IGnssXtra::setCallback */
                        req = gbinder_client_new_request (priv->m_client_gnssXtra);
                        gbinder_local_request_append_local_object (req, priv->m_callback_gnssXtra);
                        reply = gbinder_client_transact_sync_reply (priv->m_client_gnssXtra,
                                                                    GNSS_XTRA_SET_CALLBACK, req, &status);

                        if (status || !is_reply_success (reply))
                                g_debug ("Initialising GNSS Xtra interface failed");

                        gbinder_local_request_unref (req);
                }
        }
        gbinder_remote_reply_unref (reply);
}

gboolean
gclue_binder_gnssXtraInjectXtraData (GClueBinder *binder,
                                     gchar       *xtraData)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        gboolean ret = FALSE;
        if (priv->m_client_gnssXtra) {
                int status = 0;

                GBinderLocalRequest *req;
                GBinderRemoteReply *reply;

                req = gbinder_client_new_request (priv->m_client_gnssXtra);
                gbinder_local_request_append_hidl_string (req, xtraData);
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnssXtra,
                                                            GNSS_XTRA_INJECT_XTRA_DATA, req, &status);

                if (!status)
                        ret = is_reply_success (reply);

                if (!ret)
                        g_debug ("GNSS Xtra inject xtra data failed");

                gbinder_local_request_unref (req);
                gbinder_remote_reply_unref (reply);
        }
        return ret;
}

void
gclue_binder_aGnssInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        GBinderRemoteReply *reply;
        int status = 0;
        gboolean supl_ret = FALSE;
        const char *supl = NULL;

        if (priv->m_gnss2_available)
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss_2_0, GNSS_GET_EXTENSION_AGNSS_2_0, NULL, &status);
        else
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss, GNSS_GET_EXTENSION_AGNSS, NULL, &status);

        if (!status) {
                priv->m_remote_agnss = get_extension_object (reply);

                if (priv->m_remote_agnss) {
                        g_debug ("Initialising AGNSS interface");
                        GBinderLocalRequest *req;

                        if (priv->m_gnss2_available)
                                priv->m_client_agnss = gbinder_client_new (priv->m_remote_agnss, AGNSS_REMOTE_2_0);
                        else
                                priv->m_client_agnss = gbinder_client_new (priv->m_remote_agnss, AGNSS_REMOTE);

                        priv->m_callback_agnss = gbinder_servicemanager_new_local_object (priv->m_sm, AGNSS_CALLBACK, gclue_binder_agnss_cb, binder);

                        gbinder_remote_reply_unref (reply);

                        /* IAGnss::setCallback */
                        req = gbinder_client_new_request (priv->m_client_agnss);
                        gbinder_local_request_append_local_object (req, priv->m_callback_agnss);
                        reply = gbinder_client_transact_sync_reply (priv->m_client_agnss,
                                                                    AGNSS_SET_CALLBACK, req, &status);

                        if (!status) {
                                if (!gbinder_remote_reply_read_int32 (reply, &status) || status != 0)
                                        g_debug ("Initialising AGNSS interface failed %d", status);
                        }


                        supl = get_supl_server_config ();
                        if (supl != NULL) {
                                char *supl_domain = NULL;
                                int supl_port = 0;

                                supl_ret = parse_supl_string (supl, &supl_domain, &supl_port);
                                if (supl_ret) {
                                        supl_ret = gclue_binder_aGnssSetServer (binder, BINDER_APN_IP_IPV4, supl_domain, supl_port);
                                        if (supl_ret)
                                                g_debug ("SUPL server %s:%d has been set successfully", supl_domain, supl_port);
                                        else
                                                g_debug ("Failed to set %s:%d SUPL server", supl_domain, supl_port);

                                        g_free (supl_domain);
                                }
                        }

                        gbinder_local_request_unref (req);
                }
        }
        gbinder_remote_reply_unref (reply);
}

gboolean
gclue_binder_aGnssDataConnClosed (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        int status = 0;
        gboolean ret = FALSE;
        GBinderRemoteReply *reply;

        reply = gbinder_client_transact_sync_reply (priv->m_client_agnss,
                                                    AGNSS_DATA_CONN_CLOSED, NULL, &status);

        if (!status)
                ret = is_reply_success (reply);

        gbinder_remote_reply_unref (reply);
        return ret;
}

gboolean
gclue_binder_aGnssDataConnFailed (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        int status = 0;
        gboolean ret = FALSE;
        GBinderRemoteReply *reply;

        reply = gbinder_client_transact_sync_reply (priv->m_client_agnss,
                                                    AGNSS_DATA_CONN_FAILED, NULL, &status);

        if (!status)
                ret = is_reply_success (reply);

        gbinder_remote_reply_unref (reply);
        return ret;
}

gboolean
gclue_binder_aGnssDataConnOpen (GClueBinder *binder,
                                const char  *apn,
                                const char  *protocol)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        int status = 0;
        gboolean ret = FALSE;
        GBinderLocalRequest *req;
        GBinderRemoteReply *reply;
        GBinderWriter writer;

        req = gbinder_client_new_request (priv->m_client_agnss);

        gbinder_local_request_init_writer (req, &writer);
        gbinder_writer_append_hidl_string (&writer, apn);
        gbinder_writer_append_int32 (&writer, protocol_to_apn_type (protocol));
        reply = gbinder_client_transact_sync_reply (priv->m_client_agnss,
                                                    AGNSS_DATA_CONN_OPEN, req, &status);

        if (!status)
                ret = is_reply_success (reply);

        gbinder_local_request_unref (req);
        gbinder_remote_reply_unref (reply);

        return ret;
}

gboolean
gclue_binder_aGnssSetServer (GClueBinder    *binder,
                             BinderAGnssType type,
                             const char     *hostname,
                             int             port)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        int status = 0;
        gboolean ret = FALSE;
        GBinderLocalRequest *req;
        GBinderRemoteReply *reply;
        GBinderWriter writer;

        req = gbinder_client_new_request (priv->m_client_agnss);

        gbinder_local_request_init_writer (req, &writer);
        gbinder_writer_append_int32 (&writer, type);
        gbinder_writer_append_hidl_string (&writer, hostname);
        gbinder_writer_append_int32 (&writer, port);
        reply = gbinder_client_transact_sync_reply (priv->m_client_agnss,
                                                    AGNSS_SET_SERVER, req, &status);

        if (!status)
                ret = is_reply_success (reply);

        gbinder_local_request_unref (req);
        gbinder_remote_reply_unref (reply);

        return ret;
}

gboolean
gclue_binder_aGnssRilsetSetId (GClueBinder *binder,
                               int          type,
                               const char  *setid)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_val_if_fail (GCLUE_IS_BINDER (binder), FALSE);
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        int status = 0;
        gboolean ret = FALSE;
        GBinderLocalRequest *req;
        GBinderRemoteReply *reply;
        GBinderWriter writer;

        req = gbinder_client_new_request (priv->m_client_agnssRil);

        gbinder_local_request_init_writer (req, &writer);
        gbinder_writer_append_int32 (&writer, type);
        gbinder_writer_append_hidl_string (&writer, setid);
        reply = gbinder_client_transact_sync_reply (priv->m_client_agnssRil,
                                                    AGNSS_RIL_SET_SET_ID, req, &status);

        if (!status)
               ret = is_reply_success (reply);

        gbinder_local_request_unref (req);
        gbinder_remote_reply_unref (reply);

        return ret;
}

void
gclue_binder_aGnssRilInit (GClueBinder *binder)
{
        GClueBinder *hbinder;
        GClueBinderPrivate *priv;
        g_return_if_fail (GCLUE_IS_BINDER (binder));
        hbinder = GCLUE_BINDER (binder);
        priv = hbinder->priv;

        GBinderRemoteReply *reply;
        int status = 0;

        if (priv->m_gnss2_available)
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss_2_0, GNSS_GET_EXTENSION_AGNSS_RIL_2_0, NULL, &status);
        else
                reply = gbinder_client_transact_sync_reply (priv->m_client_gnss, GNSS_GET_EXTENSION_AGNSS_RIL, NULL, &status);

        if (!status) {
                priv->m_remote_agnssRil = get_extension_object (reply);

                if (priv->m_remote_agnssRil) {
                        g_debug ("Initialising AGNSS RIL interface");
                        GBinderLocalRequest *req;

                        if (priv->m_gnss2_available)
                                priv->m_client_agnssRil = gbinder_client_new (priv->m_remote_agnssRil, AGNSS_RIL_REMOTE_2_0);
                        else
                                priv->m_client_agnssRil = gbinder_client_new (priv->m_remote_agnssRil, AGNSS_RIL_REMOTE);

                        priv->m_client_agnssRil = gbinder_client_new (priv->m_remote_agnssRil, AGNSS_RIL_REMOTE);
                        priv->m_callback_agnssRil = gbinder_servicemanager_new_local_object (priv->m_sm, AGNSS_RIL_CALLBACK, gclue_binder_agnss_ril_cb, binder);

                        gbinder_remote_reply_unref (reply);

                        /* IAGnssRil::setCallback */
                        req = gbinder_client_new_request (priv->m_client_agnssRil);
                        gbinder_local_request_append_local_object (req, priv->m_callback_agnssRil);
                        reply = gbinder_client_transact_sync_reply (priv->m_client_agnssRil,
                                                                    AGNSS_RIL_SET_CALLBACK, req, &status);

                        if (!status) {
                                if (!gbinder_remote_reply_read_int32 (reply, &status) || status != 0)
                                        g_debug ("Initialising AGNSS RIL interface failed %d", status);
                        }

                        gbinder_local_request_unref (req);
                }
        }
        gbinder_remote_reply_unref (reply);
}
