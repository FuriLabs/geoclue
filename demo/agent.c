/* vim: set et ts=8 sw=8: */
/* agent.c
 *
 * Copyright 2013 Red Hat, Inc.
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
 * Author: Zeeshan Ali (Khattak) <zeeshanak@gnome.org>
 */
#include <config.h>

#include <gio/gio.h>
#include <locale.h>
#include <glib/gi18n.h>
#include <stdlib.h>
#include <libnotify/notify.h>

#include "gclue-service-agent.h"

/* Commandline options */
static gboolean version;

static GOptionEntry entries[] =
{
        { "version",
          0,
          0,
          G_OPTION_ARG_NONE,
          &version,
          N_("Display version number"),
          NULL },
        { NULL }
};

GClueServiceAgent *agent = NULL;

static void
on_get_bus_ready (GObject      *source_object,
                  GAsyncResult *res,
                  gpointer      user_data)
{
        g_autoptr(GError) error = NULL;
        GDBusConnection *connection;

        connection = g_bus_get_finish (res, &error);
        if (connection == NULL) {
                g_critical ("Failed to get connection to system bus: %s",
                            error->message);

                exit (-2);
        }

        agent = gclue_service_agent_new (connection);
}

#define ABS_PATH ABS_SRCDIR "/agent"

static void
activate_cb (GApplication *app,
             gpointer      user_data)
{
        g_bus_get (G_BUS_TYPE_SYSTEM,
                   NULL,
                   on_get_bus_ready,
                   NULL);

        g_application_hold (app);
}

static void
is_registered_cb (GApplication *app,
                  GParamSpec   *pspec,
                  gpointer      user_data)
{
        if (g_application_get_is_registered (app) && g_application_get_is_remote (app))
                g_message ("Another instance of GeoClue DemoAgent is running.");
}

int
main (int argc, char **argv)
{
        g_autoptr (GApplication) app = NULL;
        int status = 0;
        GError *error = NULL;
        GOptionContext *context;

        setlocale (LC_ALL, "");

        textdomain (GETTEXT_PACKAGE);
        bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
        bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
        g_set_application_name ("GeoClue Agent");

        notify_init (_("GeoClue"));

        context = g_option_context_new ("- Geoclue Agent service");
        g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
        if (!g_option_context_parse (context, &argc, &argv, &error)) {
                g_critical ("option parsing failed: %s\n", error->message);
                exit (-1);
        }

        if (version) {
                g_print ("%s\n", PACKAGE_VERSION);
                exit (0);
        }

        app = g_application_new ("org.freedesktop.GeoClue2.DemoAgent",
                                 G_APPLICATION_DEFAULT_FLAGS);
        g_signal_connect (app, "activate", G_CALLBACK (activate_cb), NULL);
        g_signal_connect (app, "notify::is-registered", G_CALLBACK (is_registered_cb), NULL);

        status = g_application_run (G_APPLICATION (app), argc, argv);

        if (agent != NULL)
                g_object_unref (agent);

        return status;
}
