package tigase.db.jdbc;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import tigase.db.AuthRepository;
import tigase.db.AuthorizationException;
import tigase.db.DBInitException;
import tigase.db.DataRepository;
import tigase.db.RepositoryFactory;
import tigase.db.TigaseDBException;
import tigase.db.UserExistsException;
import tigase.db.UserNotFoundException;
import tigase.util.Algorithms;
import tigase.util.Base64;
import tigase.util.TigaseStringprepException;
import tigase.xmpp.BareJID;

import static tigase.db.AuthRepository.Meta;

@Meta( isDefault=true, supportedUris = { "jdbc:[^:]+:.*" } )
public class ShopCustomAuth implements AuthRepository {

	private static final Logger log = Logger.getLogger(ShopCustomAuth.class.getName());

	public static final String DEF_CONNVALID_KEY = "conn-valid-query";
	public static final String DEF_INITDB_KEY = "init-db-query";
	public static final String DEF_ADDUSER_KEY = "add-user-query";
	public static final String DEF_DELUSER_KEY = "del-user-query";
	public static final String DEF_GETPASSWORD_KEY = "get-password-query";
	public static final String DEF_UPDATEPASSWORD_KEY = "update-password-query";
	public static final String DEF_USERLOGIN_KEY = "user-login-query";
	public static final String DEF_USERLOGOUT_KEY = "user-logout-query";
	public static final String DEF_USERS_COUNT_KEY = "users-count-query";
	public static final String DEF_USERS_DOMAIN_COUNT_KEY = "" + "users-domain-count-query";
	public static final String DEF_LISTDISABLEDACCOUNTS_KEY= "users-list-disabled-accounts-query";
	public static final String DEF_DISABLEACCOUNT_KEY = "user-disable-account-query";
	public static final String DEF_ENABLEACCOUNT_KEY = "user-enable-account-query";
	public static final String DEF_NONSASL_MECHS_KEY = "non-sasl-mechs";
	public static final String DEF_SASL_MECHS_KEY = "sasl-mechs";
	public static final String NO_QUERY = "none";
	public static final String DEF_INITDB_QUERY = "{ call TigInitdb() }";
	public static final String DEF_ADDUSER_QUERY = "{ call TigAddUserPlainPw(?, ?) }";
	public static final String DEF_DELUSER_QUERY = "{ call TigRemoveUser(?) }";
	public static final String DEF_GETPASSWORD_QUERY = "{ call TigGetPassword(?) }";
	public static final String DEF_UPDATEPASSWORD_QUERY = "{ call TigUpdatePasswordPlainPwRev(?, ?) }";
	public static final String DEF_USERLOGIN_QUERY = "{ call TigUserLoginPlainPw(?, ?) }";
	public static final String DEF_USERLOGOUT_QUERY = "{ call TigUserLogout(?) }";
	public static final String DEF_USERS_COUNT_QUERY = "{ call TigAllUsersCount() }";
	public static final String DEF_USERS_DOMAIN_COUNT_QUERY = ""  + "select count(*) from tig_users where user_id like ?";
	public static final String DEF_LISTDISABLEDACCOUNTS_QUERY = "{ call TigDisabledAccounts() }";
	public static final String DEF_DISABLEACCOUNT_QUERY = "{ call TigDisableAccount(?) }";
	public static final String DEF_ENABLEACCOUNT_QUERY = "{ call TigEnableAccount(?) }";
	public static final String DEF_NONSASL_MECHS = "password";
	public static final String DEF_SASL_MECHS = "PLAIN";
	public static final String SP_STARTS_WITH = "{ call";

	private DataRepository data_repo = null;
	private String initdb_query = DEF_INITDB_QUERY;
	private String getpassword_query = DEF_GETPASSWORD_QUERY;
	private String deluser_query = DEF_DELUSER_QUERY;
	private String adduser_query = DEF_ADDUSER_QUERY;
	private String updatepassword_query = DEF_UPDATEPASSWORD_QUERY;
	private String userlogin_query = DEF_USERLOGIN_QUERY;
	private String userdomaincount_query = DEF_USERS_DOMAIN_COUNT_QUERY;
	private String listdisabledaccounts_query = DEF_LISTDISABLEDACCOUNTS_QUERY;
	private String disableaccount_query = DEF_DISABLEACCOUNT_QUERY;
	private String enableaccount_query = DEF_ENABLEACCOUNT_QUERY;
	private String userlogout_query = null;
	private String userscount_query = DEF_USERS_COUNT_QUERY;
	private boolean userlogin_active = false;
	private String[] sasl_mechs = DEF_SASL_MECHS.split(",");
	private String[] nonsasl_mechs = DEF_NONSASL_MECHS.split(",");

	@Override
	public void initRepository(final String connection_str, Map<String, String> params)
			throws DBInitException {
		try {
			data_repo = RepositoryFactory.getDataRepository(null, connection_str, params);
			initdb_query = getParamWithDef(params, DEF_INITDB_KEY, DEF_INITDB_QUERY);

			if (initdb_query != null) {
				data_repo.initPreparedStatement(initdb_query, initdb_query);
			}

			adduser_query = getParamWithDef(params, DEF_ADDUSER_KEY, DEF_ADDUSER_QUERY);

			if ((adduser_query != null)) {
				data_repo.initPreparedStatement(adduser_query, adduser_query);
			}

			deluser_query = getParamWithDef(params, DEF_DELUSER_KEY, DEF_DELUSER_QUERY);

			if ((deluser_query != null)) {
				data_repo.initPreparedStatement(deluser_query, deluser_query);
			}

			getpassword_query = getParamWithDef(params, DEF_GETPASSWORD_KEY, DEF_GETPASSWORD_QUERY);

			if ((getpassword_query != null)) {
				data_repo.initPreparedStatement(getpassword_query, getpassword_query);
			}

			updatepassword_query =
					getParamWithDef(params, DEF_UPDATEPASSWORD_KEY, DEF_UPDATEPASSWORD_QUERY);

			if ((updatepassword_query != null)) {
				data_repo.initPreparedStatement(updatepassword_query, updatepassword_query);
			}

			userlogin_query = getParamWithDef(params, DEF_USERLOGIN_KEY, DEF_USERLOGIN_QUERY);
			if (userlogin_query  != null) {
				data_repo.initPreparedStatement(userlogin_query, userlogin_query);
				userlogin_active = true;
			}

			userlogout_query =
					getParamWithDef(params, DEF_USERLOGOUT_KEY, DEF_USERLOGOUT_QUERY);

			if ((userlogout_query != null)) {
				data_repo.initPreparedStatement(userlogout_query, userlogout_query);
			}

			userscount_query =
					getParamWithDef(params, DEF_USERS_COUNT_KEY, DEF_USERS_COUNT_QUERY);

			if ((userscount_query != null)) {
				data_repo.initPreparedStatement(userscount_query, userscount_query);
			}

			userdomaincount_query =
					getParamWithDef(params, DEF_USERS_DOMAIN_COUNT_KEY,
							DEF_USERS_DOMAIN_COUNT_QUERY);

			if ((userdomaincount_query != null)) {
				data_repo.initPreparedStatement(userdomaincount_query, userdomaincount_query);
			}

			listdisabledaccounts_query = getParamWithDef(params, DEF_LISTDISABLEDACCOUNTS_KEY,
					DEF_LISTDISABLEDACCOUNTS_QUERY);
			if (listdisabledaccounts_query != null) {
				data_repo.initPreparedStatement(listdisabledaccounts_query, listdisabledaccounts_query);
			}

			disableaccount_query = getParamWithDef(params, DEF_DISABLEACCOUNT_KEY,
					DEF_DISABLEACCOUNT_QUERY);
			if (disableaccount_query != null) {
				data_repo.initPreparedStatement(disableaccount_query, disableaccount_query);
			}

			enableaccount_query = getParamWithDef(params, DEF_ENABLEACCOUNT_KEY,
					DEF_ENABLEACCOUNT_QUERY);
			if (enableaccount_query != null) {
				data_repo.initPreparedStatement(enableaccount_query, enableaccount_query);
			}

			nonsasl_mechs =
					getParamWithDef(params, DEF_NONSASL_MECHS_KEY, DEF_NONSASL_MECHS).split(",");
			sasl_mechs = getParamWithDef(params, DEF_SASL_MECHS_KEY, DEF_SASL_MECHS).split(",");

			if ((params != null) && (params.get("init-db") != null)) {
				initDb();
			}
		} catch (Exception e) {
			data_repo = null;

			throw new DBInitException(
					"Problem initializing jdbc connection: " + connection_str, e);
		}
	}

	protected String getParamWithDef(Map<String, String> params, String key, String def) {
		if (params == null) {
			return def;
		}

		String result = params.get(key);

		if (result != null) {
			log.log(Level.CONFIG, "Custom query loaded for ''{0}'': ''{1}''", new Object[] {
					key, result });
		} else {
			result = def;
			log.log(Level.CONFIG, "Default query loaded for ''{0}'': ''{1}''", new Object[] {
					key, def });
		}

		if (result != null) {
			result = result.trim();

			if (result.isEmpty() || result.equals(NO_QUERY)) {
				result = null;
			}
		}

		return result;
	}

	private void initDb() throws SQLException {
		if (initdb_query == null) {
			return;
		}

		PreparedStatement init_db = data_repo.getPreparedStatement(null, initdb_query);

		synchronized (init_db) {
			init_db.executeUpdate();
		}
	}

	@Override
	public boolean plainAuth(BareJID user, String password) throws UserNotFoundException, TigaseDBException, AuthorizationException {
		return false;
	}

	@Override
	public void addUser(BareJID user, String password) throws UserExistsException, TigaseDBException {

	}

	@Override
	public boolean digestAuth(BareJID user, String digest, String id, String alg) throws UserNotFoundException, TigaseDBException, AuthorizationException {
		return false;
	}

	@Override
	public String getResourceUri() {
		return null;
	}

	@Override
	public long getUsersCount() {
		return 0;
	}

	@Override
	public long getUsersCount(String domain) {
		return 0;
	}

	@Override
	public void logout(BareJID user) throws UserNotFoundException, TigaseDBException {

	}

	@Override
	public boolean otherAuth(Map<String, Object> authProps) throws UserNotFoundException, TigaseDBException, AuthorizationException {
		return false;
	}

	@Override
	public void queryAuth(Map<String, Object> authProps) {

	}

	@Override
	public void removeUser(BareJID user) throws UserNotFoundException, TigaseDBException {

	}

	@Override
	public String getPassword(BareJID user) throws UserNotFoundException, TigaseDBException {
		return null;
	}

	@Override
	public void updatePassword(BareJID user, String password) throws UserNotFoundException, TigaseDBException {

	}

	@Override
	public boolean isUserDisabled(BareJID user) throws UserNotFoundException, TigaseDBException {
		return false;
	}

	@Override
	public void setUserDisabled(BareJID user, Boolean value) throws UserNotFoundException, TigaseDBException {

	}
}