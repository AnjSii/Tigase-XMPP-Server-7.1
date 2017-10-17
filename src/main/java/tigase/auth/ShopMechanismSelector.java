package tigase.auth;

import javax.security.sasl.SaslServerFactory;

import tigase.auth.mechanisms.ShopSaslServerFactory;
import tigase.auth.mechanisms.TigaseSaslServerFactory;
import tigase.xmpp.XMPPResourceConnection;

public class ShopMechanismSelector extends DefaultMechanismSelector {

	protected boolean match(SaslServerFactory factory, String mechanismName, XMPPResourceConnection session) {
		return !(session.isTlsRequired() && !session.isEncrypted()) &&
			factory instanceof TigaseSaslServerFactory && mechanismName.equals("PLAIN");
	}
}
