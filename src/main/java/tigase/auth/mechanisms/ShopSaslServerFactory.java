package tigase.auth.mechanisms;

import java.util.Map;

public class ShopSaslServerFactory extends TigaseSaslServerFactory {

	@Override
	public String[] getMechanismNames(Map<String, ?> props) {
		return new String[] {
			"PLAIN",
		};
	}
}
