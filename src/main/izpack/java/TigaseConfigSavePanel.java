/*
 * Tigase Jabber/XMPP Server
 * Copyright (C) 2004-2007 "Artur Hefczyc" <artur.hefczyc@tigase.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 *
 * $Rev$
 * Last modified by $Author$
 * $Date$
 */

package com.izforge.izpack.panels;

import java.io.File;
import java.io.FileWriter;
import java.util.Map;
import java.util.Properties;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.izforge.izpack.gui.IzPanelLayout;
import com.izforge.izpack.installer.AutomatedInstallData;
import com.izforge.izpack.installer.InstallData;
import com.izforge.izpack.installer.InstallerFrame;
import com.izforge.izpack.installer.IzPanel;
import com.izforge.izpack.util.Debug;
import com.izforge.izpack.util.OsVersion;

/**
 * The Hello panel class.
 *
 * @author <a href="mailto:artur.hefczyc@tigase.org">Artur Hefczyc</a>
 * @version $Rev$
 */
public class TigaseConfigSavePanel extends IzPanel {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	private JTextArea textArea = null;

	private final TigaseConfigSaveHelper helper = new TigaseConfigSaveHelper();


	/**
	 * The constructor.
	 *
	 * @param parent The parent.
	 * @param idata  The installation data.
	 */
	public TigaseConfigSavePanel(InstallerFrame parent, InstallData idata) {
		super(parent, TigaseInstallerCommon.init(idata), new IzPanelLayout());

		// The config label.
		String msg = parent.langpack.getString("TigaseConfigSavePanel.info");
		add(createMultiLineLabel(msg));
		add(IzPanelLayout.createParagraphGap());
		// The text area which shows the info.
		textArea = new JTextArea("");
		textArea.setCaretPosition(0);
		textArea.setEditable(true);
		JScrollPane scroller = new JScrollPane(textArea);
		add(scroller, NEXT_LINE);
		// At end of layouting we should call the completeLayout method also they do nothing.
		getLayoutHelper().completeLayout();
	}

	public void panelActivate() {
		super.panelActivate();
		String config = helper.showConfig(idata);
		textArea.setText(config);
	}



	/**
	 * Indicates wether the panel has been validated or not.
	 *
	 * @return Always true.
	 */
	public boolean isValidated() {
		String errorStr =  helper.saveConfig(idata, textArea.getText());
		if (errorStr != null) {
			emitError("Can not write to config file", errorStr);
		}
		return true;
	}

}

class TigaseConfigSaveHelper {
	
	String showConfig(AutomatedInstallData idata) {
		TigaseConfigConst.props = new Properties();
		StringBuilder config = new StringBuilder();
		int comp_idx = 0;
		for (Map.Entry<String, String> entry:
        TigaseConfigConst.tigaseIzPackMap.entrySet()) {
			String varName = entry.getValue();
			String varValue = idata.getVariable(varName);

			if (varName.equals(TigaseConfigConst.DEBUG)) {
				String debugVar = getDebugs(idata);
				if (!debugVar.isEmpty()) {
					TigaseConfigConst.props.setProperty(entry.getKey(), debugVar);
				}
				Debug.trace("Set: " + entry.getKey() + " = " + debugVar);
				continue;
			}
			if (varName.equals(TigaseConfigConst.PLUGINS)) {
				String pluginsVar = getPlugins(idata);
				if (!pluginsVar.isEmpty()) {
					TigaseConfigConst.props.setProperty(entry.getKey(), pluginsVar);
				}
				Debug.trace("Set: " + entry.getKey() + " = " + pluginsVar);
				continue;
			}
			if (varName.equals(TigaseConfigConst.USER_DB_URI)) {
				TigaseConfigConst.props.setProperty(entry.getKey(), getDBUri(idata));
				TigaseConfigConst.props.setProperty("root-tigase-db-uri",
					getRootTigaseDBUri(idata));
				TigaseConfigConst.props.setProperty("root-db-uri", getRootDBUri(idata));
				Debug.trace("Set: " + entry.getKey() + " = " + getDBUri(idata));
				continue;
			}

			if (varValue == null) continue;

			if (varName.equals(TigaseConfigConst.DB_TYPE)) {
				TigaseConfigConst.props.setProperty(entry.getKey(), getUserDB(idata));
				Debug.trace("Set: " + entry.getKey() + " = " + getUserDB(idata));
				continue;
			}
			if (varName.equals(TigaseConfigConst.AUTH_HANDLE)) {
				TigaseConfigConst.props.setProperty(entry.getKey(),
					getAuthHandler(varValue, idata));
				Debug.trace("Set: " + entry.getKey() + " = " + getAuthHandler(varValue, idata));
				continue;
			}
			if (varName.equals(TigaseConfigConst.MUC_COMP)) {
				if (varValue.equals("on")) {
					++comp_idx;
					TigaseConfigConst.props.setProperty("--comp-name-"+comp_idx, "muc");
					TigaseConfigConst.props.setProperty("--comp-class-"+comp_idx,
						"tigase.muc.MUCComponent");
				}
				Debug.trace("Set: " + "--comp-name-"+comp_idx + " = " + "muc");
				continue;
			}
			if (varName.equals(TigaseConfigConst.PUBSUB_COMP)) {
				if (varValue.equals("on")) {
					++comp_idx;
					TigaseConfigConst.props.setProperty("--comp-name-"+comp_idx, "pubsub");
					TigaseConfigConst.props.setProperty("--comp-class-"+comp_idx,
						"tigase.pubsub.PubSubClusterComponent");
				}
				Debug.trace("Set: " + "--comp-name-"+comp_idx + " = " + "pubsub");
				continue;
			}
			if (varName.equals(TigaseConfigConst.AUTH_DB_URI)) {
				String auth_db_uri = getAuthUri(idata);
				if (auth_db_uri != null) {
					TigaseConfigConst.props.setProperty(entry.getKey(), auth_db_uri);
					Debug.trace("Set: " + entry.getKey() + " = " + auth_db_uri);
				} else {
					Debug.trace("Not set: " + entry.getKey());
				}
				continue;
			}
			if (!varValue.trim().isEmpty()) {
				TigaseConfigConst.props.setProperty(entry.getKey(), varValue);
			}
			Debug.trace("Set: " + entry.getKey() + " = " + varValue);
		}
		for (String name: TigaseConfigConst.props.stringPropertyNames()) {
			if (!name.startsWith("root")) {
				config.append(name + " = " + TigaseConfigConst.props.getProperty(name) + "\n");
			}
		}
		return config.toString();
	}

	private String getDBUri(AutomatedInstallData idata) {
		String db_uri = "jdbc:";
		String database = getUserDB(idata);
		if (database.equals("pgsql")) {
			db_uri += "postgresql:";
		} else {
			db_uri += database + ":";
		}
		if (database.equals("derby")) {
			String derby_path = idata.getVariable("DerbyDBPath");
			if (OsVersion.IS_WINDOWS) {
				derby_path = derby_path.replace("\\", "\\\\");
			}
			db_uri += derby_path;
		} else {
			db_uri += "//" + idata.getVariable("dbHost");
			db_uri += "/" + idata.getVariable("dbName");
			db_uri += "?user=" + idata.getVariable("dbUser");
			if (idata.getVariable("dbPass") != null
				&& !idata.getVariable("dbPass").isEmpty()) {
				db_uri += "&password=" + idata.getVariable("dbPass");
			}
		}
		return db_uri;
	}

	private String getRootTigaseDBUri(AutomatedInstallData idata) {
		String db_uri = "jdbc:";
		String database = getUserDB(idata);
		if (database.equals("pgsql")) {
			db_uri += "postgresql:";
		} else {
			db_uri += database + ":";
		}
		if (database.equals("derby")) {
			db_uri += idata.getVariable("DerbyDBPath") + ";create=true";
		} else {
			db_uri += "//" + idata.getVariable("dbHost");
			db_uri += "/" + idata.getVariable("dbName");
			db_uri += "?user=" + idata.getVariable("dbSuperuser");
			if (idata.getVariable("dbSuperpass") != null
				&& !idata.getVariable("dbSuperpass").isEmpty()) {
				db_uri += "&password=" + idata.getVariable("dbSuperpass");
			}
		}
		return db_uri;
	}

	private String getRootDBUri(AutomatedInstallData idata) {
		String db_uri = "jdbc:";
		String db = "";
		String database = getUserDB(idata);
		if (database.equals("pgsql")) {
			db_uri += "postgresql:";
			db = "/postgres";
		} else {
			db_uri += database + ":";
			if (database.equals("mysql")) {
				db = "/mysql";
			}
		}
		if (database.equals("derby")) {
			db_uri += idata.getVariable("DerbyDBPath") + ";create=true";
		} else {
			db_uri += "//" + idata.getVariable("dbHost");
			db_uri += db;
			db_uri += "?user=" + idata.getVariable("dbSuperuser");
			if (idata.getVariable("dbSuperpass") != null
				&& !idata.getVariable("dbSuperpass").isEmpty()) {
				db_uri += "&password=" + idata.getVariable("dbSuperpass");
			}
		}
		return db_uri;
	}

	private String getAuthUri(AutomatedInstallData idata) {
		String db_uri = "jdbc:";
		String database = idata.getVariable(TigaseConfigConst.AUTH_DB_URI);
		db_uri += database + ":";
		if (database.equals("derby")) {
			String derby_path = idata.getVariable("DerbyDBPath");
			if (derby_path != null) {
				db_uri += derby_path;
			} else {
				return null;
			}
		} else {
			db_uri += "//" + idata.getVariable("dbAuthHost");
			db_uri += "/" + idata.getVariable("dbAuthName");
			db_uri += "?user=" + idata.getVariable("dbAuthUser");
			if (idata.getVariable("dbAuthPass") != null
				&& !idata.getVariable("dbAuthPass").isEmpty()) {
				db_uri += "&password=" + idata.getVariable("dbAuthPass");
			}
		}
		return db_uri;
	}

	private String getPlugins(AutomatedInstallData idata) {
		String plugins = "";
		if (idata.getVariable(TigaseConfigConst.ALL_PLUGINS[0]) == null) {
			// The Panel with debuging settings was not shown so all
			// settins are null, then we set a default: 'server'
			return "";
		}
		for (String plugin: TigaseConfigConst.ALL_PLUGINS) {
			if (idata.getVariable(plugin) == null) {
				Debug.trace("Missing idata for: " + plugin);
				continue;
			}
			if (!idata.getVariable(plugin).equals("off")) {
				if (!plugins.isEmpty()) {
					plugins += ",";
				}
				plugins += idata.getVariable(plugin);
			}
		}
		return plugins;
	}

	private String getDebugs(AutomatedInstallData idata) {

		String debugs = "";
		if (idata.getVariable(TigaseConfigConst.ALL_DEBUGS[0]) == null) {
			// The Panel with debuging settings was not shown so all
			// settins are null, then we set a default: 'server'
			return "server";
		}
		for (String deb: TigaseConfigConst.ALL_DEBUGS) {
			if (idata.getVariable(deb) == null || idata.getVariable(deb).equals("off")) {
				continue;
			}
			if (!debugs.isEmpty()) {
				debugs += ",";
			}
			debugs += idata.getVariable(deb);
		}
		return debugs;
	}

	private String getAuthHandler(String var, AutomatedInstallData idata) {
		if (var.equals("Standard")) {
			return getUserDB(idata);
		}
		return var;
	}

	private String getUserDB(AutomatedInstallData idata) {
		String dbVar = idata.getVariable(TigaseConfigConst.DB_TYPE);
		String result = TigaseConfigConst.userDBMap.get(dbVar);
		return result != null ? result : "derby";
	}
	
	// returns null if ok, error string on error
	String saveConfig(AutomatedInstallData idata, String config) {
		// Try to read the config file.
		File configPath = null;
		File xmlConfigPath = null;
		try {
			if (idata.getVariable("searchTigaseHome") == null
				|| idata.getVariable("searchTigaseHome").isEmpty()) {
				configPath = new File(idata.getVariable("INSTALL_PATH"),
					"etc/init.properties");
				xmlConfigPath = new File(idata.getVariable("INSTALL_PATH"),
					"etc/tigase.xml");
			} else {
				configPath = new File(idata.getVariable("searchTigaseHome"),
					"etc/init.properties");
				xmlConfigPath = new File(idata.getVariable("searchTigaseHome"),
					"etc/tigase.xml");
			}
			FileWriter fw = new FileWriter(configPath, false);
			fw.write(config);
			fw.close();
			if (xmlConfigPath.exists()) {
				xmlConfigPath.delete();
			}
		} catch (Exception err) {
			String error = "Error : could not write to the config file: " + configPath + "\n";
			error += err.toString() + "\n";
			for (StackTraceElement ste: err.getStackTrace()) {
				error += ste.toString() + "\n";
			}
			return error;
		}
		return null;
	}

}