package owl.upm.cyberthreat.owlapi;

import org.json.simple.JSONObject;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class Anomaly {
	//Different Classes from Anomaly in the Ontology
	
		private OWLDataFactory dataFactory;
		private OWLOntologyManager man;
		private String base;
		String baseO ;
		public static OWLClass wifi_sensor_anomaly;
		public static OWLClass uba_sensor_anomaly ;
		public static OWLClass rm_sensor_anomaly;
		public static OWLClass rf_sensor_anomaly;
		public static OWLClass ids_sensor_anomaly;
		public static OWLClass bt_sensor_anomaly;
		public static OWLClass event;
		public static OWLClass effect;
		
	public Anomaly (OWLDataFactory dataFactory, OWLOntologyManager man, String base) {
		this.dataFactory= dataFactory;
		this.man = man;
		this.base = "http://www.semanticweb.org/paulagarcia/ontologies/2020/2/cyberthreat_ONA";
		
		 //http://.org/2020/...#
		PrefixManager pm = new DefaultPrefixManager(this.base + "#");
		wifi_sensor_anomaly = dataFactory.getOWLClass(":WiFi_Sensor_Anomaly", pm);
		uba_sensor_anomaly = dataFactory.getOWLClass(":UBA_Sensor_Anomaly", pm);
		rm_sensor_anomaly = dataFactory.getOWLClass(":RM_Sensor_Anomaly", pm);
		rf_sensor_anomaly = dataFactory.getOWLClass(":RF_Sensor_Anomaly", pm);
		ids_sensor_anomaly = dataFactory.getOWLClass(":Cybersecurity_Sensor_Anomaly", pm);
		bt_sensor_anomaly = dataFactory.getOWLClass(":Bluetooth_Sensor_Anomaly", pm);
		event = dataFactory.getOWLClass(":Event",pm);
		effect = dataFactory.getOWLClass(":Effect",pm);
		this.baseO=base;
	}
	
	
	public static OWLClass getWifi_sensor_anomaly() {
		return wifi_sensor_anomaly;
	}


	public static void setWifi_sensor_anomaly(OWLClass wifi_sensor_anomaly) {
		Anomaly.wifi_sensor_anomaly = wifi_sensor_anomaly;
	}


	public static OWLClass getUba_sensor_anomaly() {
		return uba_sensor_anomaly;
	}


	public static void setUba_sensor_anomaly(OWLClass uba_sensor_anomaly) {
		Anomaly.uba_sensor_anomaly = uba_sensor_anomaly;
	}


	public static OWLClass getRm_sensor_anomaly() {
		return rm_sensor_anomaly;
	}


	public static void setRm_sensor_anomaly(OWLClass rm_sensor_anomaly) {
		Anomaly.rm_sensor_anomaly = rm_sensor_anomaly;
	}


	public static OWLClass getRf_sensor_anomaly() {
		return rf_sensor_anomaly;
	}


	public static void setRf_sensor_anomaly(OWLClass rf_sensor_anomaly) {
		Anomaly.rf_sensor_anomaly = rf_sensor_anomaly;
	}


	public static OWLClass getIds_sensor_anomaly() {
		return ids_sensor_anomaly;
	}


	public static void setIds_sensor_anomaly(OWLClass ids_sensor_anomaly) {
		Anomaly.ids_sensor_anomaly = ids_sensor_anomaly;
	}


	public static OWLClass getBt_sensor_anomaly() {
		return bt_sensor_anomaly;
	}


	public static void setBt_sensor_anomaly(OWLClass bt_sensor_anomaly) {
		Anomaly.bt_sensor_anomaly = bt_sensor_anomaly;
	}


	public static OWLClass getEvent() {
		return event;
	}


	public static void setEvent(OWLClass event) {
		Anomaly.event = event;
	}


	public static OWLClass getEffect() {
		return effect;
	}


	public static void setEffect(OWLClass effect) {
		Anomaly.effect = effect;
	}


	//Classify the anomalies from ddbb in the different anomaly type in the ontology
	public void  loadAnomalyInstances (OWLOntologyManager man, OWLIndividual anomaly_instance, OWLOntology o, OWLDataFactory dataFactory, JSONObject anomaly) {
       
		String type = anomaly.get("type").toString();
		if(type.equals("WF")) {
			OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(wifi_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma0);

			//Si existe evento lo anado a las caracteristicas
			/*if(!anomaly.get("event").toString().isEmpty()) {
				OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":caused_by", pm);
				String event_wifiAnomaly = anomaly.get("event").toString();
	    		OWLIndividual event_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+event_wifiAnomaly));
	    		OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(event, event_instance);
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, anomaly_instance, event_instance);
				man.addAxiom(o, axioma1);
				man.addAxiom(o, oAxiom);
			}*/
			System.out.println(axioma0);

		}
		else if(type.equals("UBA")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(uba_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(type.equals("RM")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rm_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(type.equals("RF")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rf_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(type.equals("BT")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(bt_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(type.equals("IDS")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(ids_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
    	System.out.println(anomaly_instance);	
	}
	
	public void  createAnomalyInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String anomalyType, String individualName) {
	       
		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.base +"#"+individualName));

		if(anomalyType.equals("WF")) {
			OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(wifi_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma0);

			//Si existe evento lo anado a las caracteristicas
			/*if(!anomaly.get("event").toString().isEmpty()) {
				OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":caused_by", pm);
				String event_wifiAnomaly = anomaly.get("event").toString();
	    		OWLIndividual event_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+event_wifiAnomaly));
	    		OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(event, event_instance);
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, anomaly_instance, event_instance);
				man.addAxiom(o, axioma1);
				man.addAxiom(o, oAxiom);
			}*/
			System.out.println(axioma0);

		}
		else if(anomalyType.equals("UBA")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(uba_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(anomalyType.equals("RM")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rm_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(anomalyType.equals("RF")) {
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rf_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(anomalyType.equals("BT")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(bt_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(anomalyType.equals("IDS")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(ids_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
    	System.out.println(anomaly_instance);	
	}
}