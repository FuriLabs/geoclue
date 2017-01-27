/*
 * Generated by gdbus-codegen 2.50.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __WPA_SUPPLICANT_INTERFACE_H__
#define __WPA_SUPPLICANT_INTERFACE_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1 */

#define TYPE_WPA_SUPPLICANT (wpa_supplicant_get_type ())
#define WPA_SUPPLICANT(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_SUPPLICANT, WPASupplicant))
#define IS_WPA_SUPPLICANT(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_SUPPLICANT))
#define WPA_SUPPLICANT_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), TYPE_WPA_SUPPLICANT, WPASupplicantIface))

struct _WPASupplicant;
typedef struct _WPASupplicant WPASupplicant;
typedef struct _WPASupplicantIface WPASupplicantIface;

struct _WPASupplicantIface
{
  GTypeInterface parent_iface;


  const gchar *const * (*get_interfaces) (WPASupplicant *object);

  void (*interface_added) (
    WPASupplicant *object,
    const gchar *arg_path,
    GVariant *arg_properties);

  void (*interface_removed) (
    WPASupplicant *object,
    const gchar *arg_path);

};

GType wpa_supplicant_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_supplicant_interface_info (void);
guint wpa_supplicant_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus signal emissions functions: */
void wpa_supplicant_emit_interface_added (
    WPASupplicant *object,
    const gchar *arg_path,
    GVariant *arg_properties);

void wpa_supplicant_emit_interface_removed (
    WPASupplicant *object,
    const gchar *arg_path);



/* D-Bus property accessors: */
const gchar *const *wpa_supplicant_get_interfaces (WPASupplicant *object);
gchar **wpa_supplicant_dup_interfaces (WPASupplicant *object);
void wpa_supplicant_set_interfaces (WPASupplicant *object, const gchar *const *value);


/* ---- */

#define TYPE_WPA_SUPPLICANT_PROXY (wpa_supplicant_proxy_get_type ())
#define WPA_SUPPLICANT_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_SUPPLICANT_PROXY, WPASupplicantProxy))
#define WPA_SUPPLICANT_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_SUPPLICANT_PROXY, WPASupplicantProxyClass))
#define WPA_SUPPLICANT_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_SUPPLICANT_PROXY, WPASupplicantProxyClass))
#define IS_WPA_SUPPLICANT_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_SUPPLICANT_PROXY))
#define IS_WPA_SUPPLICANT_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_SUPPLICANT_PROXY))

typedef struct _WPASupplicantProxy WPASupplicantProxy;
typedef struct _WPASupplicantProxyClass WPASupplicantProxyClass;
typedef struct _WPASupplicantProxyPrivate WPASupplicantProxyPrivate;

struct _WPASupplicantProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  WPASupplicantProxyPrivate *priv;
};

struct _WPASupplicantProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_supplicant_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPASupplicantProxy, g_object_unref)
#endif

void wpa_supplicant_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPASupplicant *wpa_supplicant_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
WPASupplicant *wpa_supplicant_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_supplicant_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPASupplicant *wpa_supplicant_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
WPASupplicant *wpa_supplicant_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define TYPE_WPA_SUPPLICANT_SKELETON (wpa_supplicant_skeleton_get_type ())
#define WPA_SUPPLICANT_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_SUPPLICANT_SKELETON, WPASupplicantSkeleton))
#define WPA_SUPPLICANT_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_SUPPLICANT_SKELETON, WPASupplicantSkeletonClass))
#define WPA_SUPPLICANT_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_SUPPLICANT_SKELETON, WPASupplicantSkeletonClass))
#define IS_WPA_SUPPLICANT_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_SUPPLICANT_SKELETON))
#define IS_WPA_SUPPLICANT_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_SUPPLICANT_SKELETON))

typedef struct _WPASupplicantSkeleton WPASupplicantSkeleton;
typedef struct _WPASupplicantSkeletonClass WPASupplicantSkeletonClass;
typedef struct _WPASupplicantSkeletonPrivate WPASupplicantSkeletonPrivate;

struct _WPASupplicantSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WPASupplicantSkeletonPrivate *priv;
};

struct _WPASupplicantSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_supplicant_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPASupplicantSkeleton, g_object_unref)
#endif

WPASupplicant *wpa_supplicant_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1.Interface */

#define TYPE_WPA_INTERFACE (wpa_interface_get_type ())
#define WPA_INTERFACE(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_INTERFACE, WPAInterface))
#define IS_WPA_INTERFACE(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_INTERFACE))
#define WPA_INTERFACE_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), TYPE_WPA_INTERFACE, WPAInterfaceIface))

struct _WPAInterface;
typedef struct _WPAInterface WPAInterface;
typedef struct _WPAInterfaceIface WPAInterfaceIface;

struct _WPAInterfaceIface
{
  GTypeInterface parent_iface;


  const gchar *const * (*get_bsss) (WPAInterface *object);

  const gchar * (*get_ifname) (WPAInterface *object);

  const gchar * (*get_state) (WPAInterface *object);

  void (*bss_added) (
    WPAInterface *object,
    const gchar *arg_path,
    GVariant *arg_properties);

  void (*bss_removed) (
    WPAInterface *object,
    const gchar *arg_path);

};

GType wpa_interface_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_interface_interface_info (void);
guint wpa_interface_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus signal emissions functions: */
void wpa_interface_emit_bss_added (
    WPAInterface *object,
    const gchar *arg_path,
    GVariant *arg_properties);

void wpa_interface_emit_bss_removed (
    WPAInterface *object,
    const gchar *arg_path);



/* D-Bus property accessors: */
const gchar *wpa_interface_get_state (WPAInterface *object);
gchar *wpa_interface_dup_state (WPAInterface *object);
void wpa_interface_set_state (WPAInterface *object, const gchar *value);

const gchar *wpa_interface_get_ifname (WPAInterface *object);
gchar *wpa_interface_dup_ifname (WPAInterface *object);
void wpa_interface_set_ifname (WPAInterface *object, const gchar *value);

const gchar *const *wpa_interface_get_bsss (WPAInterface *object);
gchar **wpa_interface_dup_bsss (WPAInterface *object);
void wpa_interface_set_bsss (WPAInterface *object, const gchar *const *value);


/* ---- */

#define TYPE_WPA_INTERFACE_PROXY (wpa_interface_proxy_get_type ())
#define WPA_INTERFACE_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_INTERFACE_PROXY, WPAInterfaceProxy))
#define WPA_INTERFACE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_INTERFACE_PROXY, WPAInterfaceProxyClass))
#define WPA_INTERFACE_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_INTERFACE_PROXY, WPAInterfaceProxyClass))
#define IS_WPA_INTERFACE_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_INTERFACE_PROXY))
#define IS_WPA_INTERFACE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_INTERFACE_PROXY))

typedef struct _WPAInterfaceProxy WPAInterfaceProxy;
typedef struct _WPAInterfaceProxyClass WPAInterfaceProxyClass;
typedef struct _WPAInterfaceProxyPrivate WPAInterfaceProxyPrivate;

struct _WPAInterfaceProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  WPAInterfaceProxyPrivate *priv;
};

struct _WPAInterfaceProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_interface_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPAInterfaceProxy, g_object_unref)
#endif

void wpa_interface_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPAInterface *wpa_interface_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
WPAInterface *wpa_interface_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_interface_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPAInterface *wpa_interface_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
WPAInterface *wpa_interface_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define TYPE_WPA_INTERFACE_SKELETON (wpa_interface_skeleton_get_type ())
#define WPA_INTERFACE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_INTERFACE_SKELETON, WPAInterfaceSkeleton))
#define WPA_INTERFACE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_INTERFACE_SKELETON, WPAInterfaceSkeletonClass))
#define WPA_INTERFACE_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_INTERFACE_SKELETON, WPAInterfaceSkeletonClass))
#define IS_WPA_INTERFACE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_INTERFACE_SKELETON))
#define IS_WPA_INTERFACE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_INTERFACE_SKELETON))

typedef struct _WPAInterfaceSkeleton WPAInterfaceSkeleton;
typedef struct _WPAInterfaceSkeletonClass WPAInterfaceSkeletonClass;
typedef struct _WPAInterfaceSkeletonPrivate WPAInterfaceSkeletonPrivate;

struct _WPAInterfaceSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WPAInterfaceSkeletonPrivate *priv;
};

struct _WPAInterfaceSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_interface_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPAInterfaceSkeleton, g_object_unref)
#endif

WPAInterface *wpa_interface_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1.BSS */

#define TYPE_WPA_BSS (wpa_bss_get_type ())
#define WPA_BSS(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_BSS, WPABSS))
#define IS_WPA_BSS(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_BSS))
#define WPA_BSS_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), TYPE_WPA_BSS, WPABSSIface))

struct _WPABSS;
typedef struct _WPABSS WPABSS;
typedef struct _WPABSSIface WPABSSIface;

struct _WPABSSIface
{
  GTypeInterface parent_iface;

  GVariant * (*get_bssid) (WPABSS *object);

  guint16  (*get_frequency) (WPABSS *object);

  gint16  (*get_signal) (WPABSS *object);

  GVariant * (*get_ssid) (WPABSS *object);

};

GType wpa_bss_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_bss_interface_info (void);
guint wpa_bss_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus property accessors: */
GVariant *wpa_bss_get_ssid (WPABSS *object);
GVariant *wpa_bss_dup_ssid (WPABSS *object);
void wpa_bss_set_ssid (WPABSS *object, GVariant *value);

GVariant *wpa_bss_get_bssid (WPABSS *object);
GVariant *wpa_bss_dup_bssid (WPABSS *object);
void wpa_bss_set_bssid (WPABSS *object, GVariant *value);

gint16 wpa_bss_get_signal (WPABSS *object);
void wpa_bss_set_signal (WPABSS *object, gint16 value);

guint16 wpa_bss_get_frequency (WPABSS *object);
void wpa_bss_set_frequency (WPABSS *object, guint16 value);


/* ---- */

#define TYPE_WPA_BSS_PROXY (wpa_bss_proxy_get_type ())
#define WPA_BSS_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_BSS_PROXY, WPABSSProxy))
#define WPA_BSS_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_BSS_PROXY, WPABSSProxyClass))
#define WPA_BSS_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_BSS_PROXY, WPABSSProxyClass))
#define IS_WPA_BSS_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_BSS_PROXY))
#define IS_WPA_BSS_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_BSS_PROXY))

typedef struct _WPABSSProxy WPABSSProxy;
typedef struct _WPABSSProxyClass WPABSSProxyClass;
typedef struct _WPABSSProxyPrivate WPABSSProxyPrivate;

struct _WPABSSProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  WPABSSProxyPrivate *priv;
};

struct _WPABSSProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_bss_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPABSSProxy, g_object_unref)
#endif

void wpa_bss_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPABSS *wpa_bss_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
WPABSS *wpa_bss_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_bss_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
WPABSS *wpa_bss_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
WPABSS *wpa_bss_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define TYPE_WPA_BSS_SKELETON (wpa_bss_skeleton_get_type ())
#define WPA_BSS_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_WPA_BSS_SKELETON, WPABSSSkeleton))
#define WPA_BSS_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_WPA_BSS_SKELETON, WPABSSSkeletonClass))
#define WPA_BSS_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_WPA_BSS_SKELETON, WPABSSSkeletonClass))
#define IS_WPA_BSS_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_WPA_BSS_SKELETON))
#define IS_WPA_BSS_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_WPA_BSS_SKELETON))

typedef struct _WPABSSSkeleton WPABSSSkeleton;
typedef struct _WPABSSSkeletonClass WPABSSSkeletonClass;
typedef struct _WPABSSSkeletonPrivate WPABSSSkeletonPrivate;

struct _WPABSSSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WPABSSSkeletonPrivate *priv;
};

struct _WPABSSSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_bss_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WPABSSSkeleton, g_object_unref)
#endif

WPABSS *wpa_bss_skeleton_new (void);


G_END_DECLS

#endif /* __WPA_SUPPLICANT_INTERFACE_H__ */
