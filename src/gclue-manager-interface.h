/*
 * Generated by gdbus-codegen 2.47.6. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __GCLUE_MANAGER_INTERFACE_H__
#define __GCLUE_MANAGER_INTERFACE_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.GeoClue2.Manager */

#define GCLUE_DBUS_TYPE_MANAGER (gclue_dbus_manager_get_type ())
#define GCLUE_DBUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), GCLUE_DBUS_TYPE_MANAGER, GClueDBusManager))
#define GCLUE_DBUS_IS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCLUE_DBUS_TYPE_MANAGER))
#define GCLUE_DBUS_MANAGER_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), GCLUE_DBUS_TYPE_MANAGER, GClueDBusManagerIface))

struct _GClueDBusManager;
typedef struct _GClueDBusManager GClueDBusManager;
typedef struct _GClueDBusManagerIface GClueDBusManagerIface;

struct _GClueDBusManagerIface
{
  GTypeInterface parent_iface;


  gboolean (*handle_add_agent) (
    GClueDBusManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_id);

  gboolean (*handle_get_client) (
    GClueDBusManager *object,
    GDBusMethodInvocation *invocation);

  guint  (*get_available_accuracy_level) (GClueDBusManager *object);

  gboolean  (*get_in_use) (GClueDBusManager *object);

};

GType gclue_dbus_manager_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *gclue_dbus_manager_interface_info (void);
guint gclue_dbus_manager_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void gclue_dbus_manager_complete_get_client (
    GClueDBusManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *client);

void gclue_dbus_manager_complete_add_agent (
    GClueDBusManager *object,
    GDBusMethodInvocation *invocation);



/* D-Bus method calls: */
void gclue_dbus_manager_call_get_client (
    GClueDBusManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean gclue_dbus_manager_call_get_client_finish (
    GClueDBusManager *proxy,
    gchar **out_client,
    GAsyncResult *res,
    GError **error);

gboolean gclue_dbus_manager_call_get_client_sync (
    GClueDBusManager *proxy,
    gchar **out_client,
    GCancellable *cancellable,
    GError **error);

void gclue_dbus_manager_call_add_agent (
    GClueDBusManager *proxy,
    const gchar *arg_id,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean gclue_dbus_manager_call_add_agent_finish (
    GClueDBusManager *proxy,
    GAsyncResult *res,
    GError **error);

gboolean gclue_dbus_manager_call_add_agent_sync (
    GClueDBusManager *proxy,
    const gchar *arg_id,
    GCancellable *cancellable,
    GError **error);



/* D-Bus property accessors: */
gboolean gclue_dbus_manager_get_in_use (GClueDBusManager *object);
void gclue_dbus_manager_set_in_use (GClueDBusManager *object, gboolean value);

guint gclue_dbus_manager_get_available_accuracy_level (GClueDBusManager *object);
void gclue_dbus_manager_set_available_accuracy_level (GClueDBusManager *object, guint value);


/* ---- */

#define GCLUE_DBUS_TYPE_MANAGER_PROXY (gclue_dbus_manager_proxy_get_type ())
#define GCLUE_DBUS_MANAGER_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), GCLUE_DBUS_TYPE_MANAGER_PROXY, GClueDBusManagerProxy))
#define GCLUE_DBUS_MANAGER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), GCLUE_DBUS_TYPE_MANAGER_PROXY, GClueDBusManagerProxyClass))
#define GCLUE_DBUS_MANAGER_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GCLUE_DBUS_TYPE_MANAGER_PROXY, GClueDBusManagerProxyClass))
#define GCLUE_DBUS_IS_MANAGER_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCLUE_DBUS_TYPE_MANAGER_PROXY))
#define GCLUE_DBUS_IS_MANAGER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), GCLUE_DBUS_TYPE_MANAGER_PROXY))

typedef struct _GClueDBusManagerProxy GClueDBusManagerProxy;
typedef struct _GClueDBusManagerProxyClass GClueDBusManagerProxyClass;
typedef struct _GClueDBusManagerProxyPrivate GClueDBusManagerProxyPrivate;

struct _GClueDBusManagerProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  GClueDBusManagerProxyPrivate *priv;
};

struct _GClueDBusManagerProxyClass
{
  GDBusProxyClass parent_class;
};

GType gclue_dbus_manager_proxy_get_type (void) G_GNUC_CONST;

void gclue_dbus_manager_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
GClueDBusManager *gclue_dbus_manager_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
GClueDBusManager *gclue_dbus_manager_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void gclue_dbus_manager_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
GClueDBusManager *gclue_dbus_manager_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
GClueDBusManager *gclue_dbus_manager_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define GCLUE_DBUS_TYPE_MANAGER_SKELETON (gclue_dbus_manager_skeleton_get_type ())
#define GCLUE_DBUS_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), GCLUE_DBUS_TYPE_MANAGER_SKELETON, GClueDBusManagerSkeleton))
#define GCLUE_DBUS_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), GCLUE_DBUS_TYPE_MANAGER_SKELETON, GClueDBusManagerSkeletonClass))
#define GCLUE_DBUS_MANAGER_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GCLUE_DBUS_TYPE_MANAGER_SKELETON, GClueDBusManagerSkeletonClass))
#define GCLUE_DBUS_IS_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCLUE_DBUS_TYPE_MANAGER_SKELETON))
#define GCLUE_DBUS_IS_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), GCLUE_DBUS_TYPE_MANAGER_SKELETON))

typedef struct _GClueDBusManagerSkeleton GClueDBusManagerSkeleton;
typedef struct _GClueDBusManagerSkeletonClass GClueDBusManagerSkeletonClass;
typedef struct _GClueDBusManagerSkeletonPrivate GClueDBusManagerSkeletonPrivate;

struct _GClueDBusManagerSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  GClueDBusManagerSkeletonPrivate *priv;
};

struct _GClueDBusManagerSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType gclue_dbus_manager_skeleton_get_type (void) G_GNUC_CONST;

GClueDBusManager *gclue_dbus_manager_skeleton_new (void);


G_END_DECLS

#endif /* __GCLUE_MANAGER_INTERFACE_H__ */
