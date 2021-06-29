
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.snmp4j.CommunityTarget;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

public class SnmpWalk2 {
	// octetString 转 二进制

	private static int[] octetStringToBytes(String value_ipar) {
		// ---------------------------
		// Split string into its parts
		// ---------------------------
		String[] bytes;
		bytes = value_ipar.split("[^0-9A-Fa-f]");

		// -----------------
		// Initialize result
		// -----------------
		int[] result;
		result = new int[bytes.length];

		// -------------
		// Convert bytes
		// -------------
		int counter;
		for (counter = 0; counter < bytes.length; counter++)
			result[counter] = Integer.parseInt(bytes[counter], 16);

		// ----
		// Done
		// ----
		return (result);

	}
	// octetString 转 Date

	private static Date octetStringToDate(String value_ipar) throws Exception {
		// ---------------------------
		// Convert into array of bytes
		// ---------------------------
		int[] bytes;
		bytes = octetStringToBytes(value_ipar);

		// -----------------------
		// Maybe nothing specified
		// -----------------------
		if (bytes[0] == 0)
			return (null);

		// ------------------
		// Extract parameters
		// ------------------
		int year;
		int month;
		int day;
		int hour;
		int minute;
		int second;
		int deci_sec = 0;
		int offset = 0;
		year = (bytes[0] * 256) + bytes[1];
		month = bytes[2];
		day = bytes[3];
		hour = bytes[4];
		minute = bytes[5];
		second = bytes[6];
		if (bytes.length >= 8)
			deci_sec = bytes[7];
		if (bytes.length >= 10) {
			offset = bytes[9] * 60;
			if (bytes.length >= 11)
				offset += bytes[10];
			if (bytes[8] == '-')
				offset = -offset;
			offset *= 60 * 1000;
		}

		// ------------------------------------
		// Get current DST and time zone offset
		// ------------------------------------
		Calendar calendar;
		int my_dst;
		int my_zone;
		calendar = Calendar.getInstance();
		my_dst = calendar.get(Calendar.DST_OFFSET);
		my_zone = calendar.get(Calendar.ZONE_OFFSET);

		// ----------------------------------
		// Compose result
		// Month to be converted into 0-based
		// ----------------------------------
		calendar.clear();
		calendar.set(Calendar.YEAR, year);
		calendar.set(Calendar.MONTH, month - 1);
		calendar.set(Calendar.DAY_OF_MONTH, day);
		calendar.set(Calendar.HOUR_OF_DAY, hour);
		calendar.set(Calendar.MINUTE, minute);
		calendar.set(Calendar.SECOND, second);
		calendar.set(Calendar.MILLISECOND, deci_sec * 100);

		// ---------
		// Reset DST
		// ---------
		calendar.add(Calendar.MILLISECOND, my_dst);

		// -----------------------------------------------------------------------------------
		// If the offset is set, we have to convert the time using the offset of
		// our time zone
		// -----------------------------------------------------------------------------------
		if (offset != 0) {
			int delta;
			delta = my_zone - offset;
			calendar.add(Calendar.MILLISECOND, delta);
		}

		// -------------
		// Return result
		// -------------
		return (calendar.getTime());

	}

	// octetString 转 中文

	private static String getChinese(String variable) {
		String result = variable;

		if (!variable.contains(":")) {
			return result;
		}

		if (result.equals(variable)) {
			try {

				String[] temps = variable.split(":");
				byte[] bs = new byte[temps.length];
				for (int i = 0; i < temps.length; i++)
					bs[i] = (byte) Integer.parseInt(temps[i], 16);
				result = new String(bs, "gbk");
			} catch (Exception ex) {

			}
		}
		return result;

	}

	public static void main(String[] args) throws Exception {
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		target.setAddress(GenericAddress.parse("udp:127.0.0.1/161")); // supply your own IP and port
		target.setRetries(2);
		target.setTimeout(1500);
		target.setVersion(SnmpConstants.version2c);

		Map<String, String> result = doWalk(".1.3.6.1.2.1.25.6.3.1", target); // ifTable, mib-2 interfaces

		for (Map.Entry<String, String> entry : result.entrySet()) {

			if (entry.getKey().startsWith(".1.3.6.1.2.1.25.6.3.1.2")) {
				System.out.println("name" + entry.getKey().replace(".1.3.6.1.2.1.25.6.3.1.2", "") + ": "
						+ getChinese(entry.getValue()));
			}
			if (entry.getKey().startsWith(".1.3.6.1.2.1.25.6.3.1.4")) {
				System.out.println("type" + entry.getKey().replace(".1.3.6.1.2.1.25.6.3.1.4", "") + ": "
						+ getChinese(entry.getValue()));
			}
			if (entry.getKey().startsWith(".1.3.6.1.2.1.25.6.3.1.5")) {
				System.out.println("datetime" + entry.getKey().replace(".1.3.6.1.2.1.25.6.3.1.5", "") + ": "
						+ octetStringToDate(entry.getValue()));
			}
		}
	}

	public static Map<String, String> doWalk(String tableOid, Target target) throws IOException {
		Map<String, String> result = new TreeMap<>();
		TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
		Snmp snmp = new Snmp(transport);
		transport.listen();

		TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
		List<TreeEvent> events = treeUtils.getSubtree(target, new OID(tableOid));
		if (events == null || events.size() == 0) {
			System.out.println("Error: Unable to read table...");
			return result;
		}

		for (TreeEvent event : events) {
			if (event == null) {
				continue;
			}
			if (event.isError()) {
				System.out.println("Error: table OID [" + tableOid + "] " + event.getErrorMessage());
				continue;
			}

			VariableBinding[] varBindings = event.getVariableBindings();
			if (varBindings == null || varBindings.length == 0) {
				continue;
			}
			for (VariableBinding varBinding : varBindings) {
				if (varBinding == null) {
					continue;
				}

				result.put("." + varBinding.getOid().toString(), varBinding.getVariable().toString());
			}

		}
		snmp.close();

		return result;
	}

}
