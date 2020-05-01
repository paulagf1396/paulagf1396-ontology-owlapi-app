package owl.upm.cyberthreat.owlapi;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Properties;

public class Configuration {
	

	public static float umbral;
	public static float intervalo;
	
	public static  final String configFilePath = "./owl-files/config.txt";
	
	public static HashMap<String, String> getPath() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(configFilePath);
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}
		
		HashMap<String, String> configValues = new HashMap<String, String>();
		configValues.put("anomaliesSVConfig", prop.getProperty("ANOMALIES.SV.CONFIG"));
		configValues.put("ficheroJSONSensores", prop.getProperty("ANOMALIES.BBDD.CONFIG"));
		configValues.put("ficheroJSONSTIX", prop.getProperty("STIX.ELEMENTS.CONFIG"));
		
		return configValues;
	}
	
	public static void getUmbral() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(getPath().get("anomaliesSVConfig"));
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}

			umbral = Float.parseFloat(prop.getProperty("SUSPICIOUS.VALUE.UMBRAL"));
			
	}
	
	public static void getIntervalo() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(getPath().get("anomaliesSVConfig"));
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}

			intervalo = Float.parseFloat(prop.getProperty("SUSPICIOUS.VALUE.INTERVALO").replace(" ", ""));
			
	}
	
	public static void runConfiguration() {
		getPath();
		getUmbral();
		getIntervalo();
	}

	
}
