/*
 * Kontalk XMPP Tigase extension
 * Copyright (C) 2017 Kontalk Devteam <devteam@kontalk.org>

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package tigase.auth;

import javax.security.sasl.SaslServerFactory;

import tigase.auth.mechanisms.ShopSaslServerFactory;
import tigase.auth.mechanisms.TigaseSaslServerFactory;
import tigase.xmpp.XMPPResourceConnection;


/**
 * SASL mechanism selector for Kontalk. Allows EXTERNAL only.
 * @author Daniele Ricci
 */
public class ShopMechanismSelector extends DefaultMechanismSelector {

    protected boolean match(SaslServerFactory factory, String mechanismName, XMPPResourceConnection session) {
    	boolean tset = session.isTlsRequired();
    	boolean tset1 = session.isEncrypted();
    	boolean tset2 = factory instanceof ShopSaslServerFactory && mechanismName.equals("PLAIN");
    	boolean tset3 = !(session.isTlsRequired() && !session.isEncrypted());
    	boolean tset4 = factory instanceof TigaseSaslServerFactory;
    	boolean tset5 = mechanismName.equals("PLAIN");
        return !(session.isTlsRequired() && !session.isEncrypted()) &&
                factory instanceof TigaseSaslServerFactory && mechanismName.equals("PLAIN");
    }

}
