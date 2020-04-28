package owl.upm.cyberthreat.owlapi;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.semanticweb.owlapi.model.AxiomType;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataPropertyDomainAxiom;
import org.semanticweb.owlapi.model.OWLDataPropertyExpression;
import org.semanticweb.owlapi.model.OWLDataPropertyRangeAxiom;
import org.semanticweb.owlapi.model.OWLDataRange;
import org.semanticweb.owlapi.model.OWLDatatype;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLLiteral;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.OWLPropertyRange;
import org.semanticweb.owlapi.model.OWLRestriction;
import org.semanticweb.owlapi.model.OWLSubClassOfAxiom;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.Node;
import org.semanticweb.owlapi.reasoner.NodeSet;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.search.Searcher;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

import com.hp.hpl.jena.util.CharEncoding;
import com.hp.hpl.jena.util.iterator.ExtendedIterator;

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
		
		Map<String, String> dataset = new HashMap<String, String>();
		
		STIX stix;
	
		
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
		stix = new STIX(dataFactory, man, this.baseO);
		
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
	public void  loadAnomalyInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, JSONObject anomaly) throws OWLOntologyStorageException {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
		
		//TYPE
		String type = anomaly.get("type").toString();
		if(type.equals("WF") && !type.isEmpty()) {
			String id = anomaly.get("id").toString();
			String name = "Anomalia"+id;
    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
			OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(wifi_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma0);
			System.out.println(axioma0);
			
			//DATA
			
	    	JSONArray data = (JSONArray) anomaly.get("data");
	    	JSONObject jObject = (JSONObject) data.get(0); 
	    	
	    	if(data.size()>0) {
	    		String field = null;
	    		field = jObject.get("userid").toString();
	    		if(field!=null) {
	    			OWLIndividual macaddr = dataFactory.getOWLNamedIndividual(IRI.create(stix.base +"#"+"userid"));
	    			OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(stix.getCyberobservableType("MAC-Addr"), macaddr); 			
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":stix_value", pmO);	
	    			createDataProperty(o, man, dataFactory, base, macaddr, dproperty, field);
	    			man.addAxiom(o, axioma1);
	    			
	    			
	    			createObjectPropertySTIX(o, man, dataFactory, base, anomaly_instance, macaddr, "related-to");
	    			
	    			//Es el dato que me interesa para saber si va a ver amenaza
	    			dataset.put(name+"_"+field, "Wifi");
	    		}
	    		
	    		field = jObject.get("pwr").toString();
	    		if(field!=null) {
	    			
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":pwr", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);

	    		}
	    		
	    		field = jObject.get("essid").toString();
	    		if(field!=null) {
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_essid", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);
	    			
	    		}
	    		
	    		
	    		OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);		
	    		initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);

    			
	    		
	    	}

		}
		else if(type.equals("UBA")) {
			String id = anomaly.get("id").toString();
			String name = "Anomalia"+id;
    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(uba_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
			
			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);	
			
			
			initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);
			
			
		}
		else if(type.equals("RM")) {
			String id = anomaly.get("id").toString();
			String name = "Anomalia"+id;
    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rm_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
			
			//DATA
			
	    	JSONArray data = (JSONArray) anomaly.get("data");
	    	JSONObject jObject = (JSONObject) data.get(0); 
	    	
	    	if(data.size()>0) {
	    		String field = null;
	    		field = jObject.get("imei").toString();
	    		if(field!=null) {
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_IMEI", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);

	    		}
	    		
	    		field = jObject.get("imsi").toString();
	    		if(field!=null) {
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_IMSI", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);

	    			
	    		}
	    		field = jObject.get("rat").toString();
	    		if(field!=null) {
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":rat", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);
	    			
	    		}
	    		
	    	}
	    	
	    	OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);	
			
			
	    	initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);

			
			
			
		}
		else if(type.equals("RF")) {	
			//DATA
			
	    	JSONArray data = (JSONArray) anomaly.get("data");
	    	if(data.size()>0) {
		    	for(int i =0; i<data.size(); i++) {
		    		String id = anomaly.get("id").toString();
					String name = "Anomalia"+id+i;
		    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
					OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(rf_sensor_anomaly, anomaly_instance);
					man.addAxiom(o, axioma);
			    	JSONObject jObject = (JSONObject) data.get(i); 

			    		String field = null;
			    		field = jObject.get("signal").toString();
			    		if(field!=null) {
			    			System.out.println(field);
			    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_signal_power", pmO);	
			    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);
		
			    		}
			    		
			    		field = jObject.get("freq").toString();
			    		if(field!=null) {
			    			System.out.println(field);
			    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_signal_frequency", pmO);	
			    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);
			    			
			    			
			    			dataset.put(name+"_"+field, "RF");
		
			    			
			    		}
			    		field = jObject.get("mod").toString();
			    		if(field!=null) {
			    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_modulation", pmO);	
			    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);
			    			
			    		}
			    		OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);	
			    		
			    		
			    		initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);

			    	}
		    	
	    	}
			
			
		}
		else if(type.equals("BT")){
			String id = anomaly.get("id").toString();
			String name = "Anomalia"+id;
    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(bt_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
			
			
			//DATA
			
	    	JSONArray data = (JSONArray) anomaly.get("data");
	    	JSONObject jObject = (JSONObject) data.get(0); 
	    	if(data.size()>0) {
	    		String field = null;
	    		field = jObject.get("rssi").toString();
	    		if(field!=null) {
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_RSSI", pmO);	
	    			createDataProperty(o, man, dataFactory, base, anomaly_instance, dproperty, field);

	    		}
	    		
	    		field = jObject.get("address").toString();
	    		if(field!=null) {
	    			OWLIndividual macaddr = dataFactory.getOWLNamedIndividual(IRI.create(stix.base +"#"+"address"));
	    			OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(stix.getCyberobservableType("MAC-Addr"), macaddr);
	    			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":stix_value", pmO);	
	    			createDataProperty(o, man, dataFactory, base, macaddr, dproperty, field);
	    			man.addAxiom(o, axioma1);
	    
	    			createObjectPropertySTIX(o, man, dataFactory, base, anomaly_instance, macaddr, "related-to"); 			
	    			
	    			dataset.put(name+"_"+field, "BT");
	    		}
	    		
	    	}
	    	
	    	OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);	
			
			
	    	initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);

			
		}
		else if(type.equals("IDS"	)){
			String id = anomaly.get("id").toString();
			String name = "Anomalia"+id;
    		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+name));
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(ids_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
			
			OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":suspicious_value", pmO);	
			
			
			initializationOfSuspiciousValue(dataFactory, anomaly_instance, dproperty,o);
			
		}
		
		
    	
		man.saveOntology(o);
    	
	}
	
	public void  createAnomalyInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String anomalyType, String individualName) {
	       
		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.baseO +"#"+individualName));

		if(anomalyType.equals("WF")) {
			OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(wifi_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma0);
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
	

	
	//Crear Data Properties
		public void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object, OWLDataProperty dproperty, String value) {
			
			// Convenience methods of OWLDataFactory for common data types:
			OWLDatatype integerDatatype = dataFactory.getIntegerOWLDatatype();
			OWLDatatype floatDatatype = dataFactory.getFloatOWLDatatype();
			OWLDatatype doubleDatatype = dataFactory.getDoubleOWLDatatype();
			OWLDatatype booleanDatatype = dataFactory.getBooleanOWLDatatype();
			
			if (dproperty!=null &&  object!=null && value!=null) {
				Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(object);
				for (OWLDataPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(object)) {
						man.removeAxiom(o, ax);
					}	
				}
				
				if(StringUtils.isNumeric(value) || StringUtils.contains(value, ".") || StringUtils.startsWith(value, "-")) {
					Set<OWLDataPropertyRangeAxiom> c = o.getAxioms(AxiomType.DATA_PROPERTY_RANGE);
					for(OWLDataPropertyRangeAxiom d : c) {
							if(d.getProperty().equals(dproperty)) {
								OWLDataRange r = d.getRange();
								if(r.equals(floatDatatype)) {
									float valuef = Float.parseFloat(value);
									System.out.println("FLOAT VALUE "+valuef);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valuef);
									man.addAxiom(o, dAxiom);
									return;
									
								}
								if(r.equals(integerDatatype)){
									int valuei = Integer.parseInt(value);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valuei);
									man.addAxiom(o, dAxiom);return;
								}
								if(r.equals(doubleDatatype)){
									double valued = Double.parseDouble(value);
									System.out.println("DOUBLE VALUE "+valued);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valued);
									man.addAxiom(o, dAxiom);return;
								}
									
							}
							
						}
					}
				
				OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, value);
				man.addAxiom(o, dAxiom);
			}else {
				System.out.println("Not properly data to create Data Property for anomaly instance");
			}
			
			
		}	
		
		//Crear Object Properties STIX
		public void createObjectPropertySTIX(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object1, OWLIndividual object2, String property) throws OWLOntologyStorageException {
			PrefixManager pm = new DefaultPrefixManager(baseO + "#");
			
			OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":"+property, pm);	
			if (oproperty!=null &&  object1!=null && object2!=null) {
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, object1, object2);
				man.addAxiom(o, oAxiom);

			}else {
				System.out.println("Not properly data to create Object Property with a STIX Object for anomaly instance");
			}
					

		}

		//Crear Object Properties DRM
		public void createObjectPropertyDRM(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String object1, String object2, String property) {
			PrefixManager pm = new DefaultPrefixManager(base + "#");
			
			OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":"+property, pm);
			OWLIndividual instance1 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object1));
			OWLIndividual instance2 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object2));
			if (oproperty!=null &&  instance1!=null && instance2!=null) {
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, instance1, instance2);
				man.addAxiom(o, oAxiom);

			}else {
				System.out.println("Not properly data to create Object Property with a DRM Object for anomaly instance");
			}

		}
		
		
		private void initializationOfSuspiciousValue(OWLDataFactory dataFactory, OWLIndividual individual, OWLDataProperty dproperty, OWLOntology o) {
			PrefixManager pm = new DefaultPrefixManager(base + "#");
			PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
			float suspicious_value = 1;		
			
			if (dproperty!=null &&  individual!=null) {
				Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
				for (OWLDataPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
						String sv = ax.getObject().getLiteral();
						suspicious_value = Float.parseFloat(sv);
						man.removeAxiom(o, ax);
						System.out.println(ax.getProperty());
						System.out.println(suspicious_value);
					}	
				}
			}
			
			
			
			
			System.out.println("SUSPICIOUS VALUE "+suspicious_value);


			
			OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, individual, suspicious_value);
			man.addAxiom(o, dAxiom);


		}
		
		public String obtainDataPropertyValue(OWLIndividual individual,OWLDataProperty dproperty, OWLOntology o, OWLReasoner reasoner) {
	         //System.out.println("obtenerValorPropiedadData");
	         //System.out.println(" individuoS: "+individuoS+", propiedadS: "+propiedadS);
	         
			System.out.println("YOU ARE IN DATA OBTAIN PROPERTY VALUE");
	         String result = null;
	         String [] piece;
	         String item;
	    
	         Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
				for (OWLDataPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
				             result = ax.getObject().getLiteral().toString();
				         }
				}
	         return(result);
	     }
		
		 
		 public String obtainObjectPropertyValue(OWLIndividual individual,OWLObjectProperty oproperty, OWLOntology o, OWLReasoner reasoner) {
	         //System.out.println("obtenerValorPropiedadObject");
	         //System.out.println(" individuoS: "+individuoS+", propiedadS: "+propiedadS);
	         System.out.println("YOU ARE IN OBTAIN OBJECT PROPERTY VALUE");
	         String result = null;
	         
	         Set<OWLObjectPropertyAssertionAxiom> properties = o.getObjectPropertyAssertionAxioms(individual);
				for (OWLObjectPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(oproperty) && ax.getSubject().equals(individual)) {
				             result = ax.getObject().toStringID();
				         }
				}
				System.out.println(result);
	         return(result);
	     }
		 
		 
		 public void modifiedSuspiciousValue(OWLIndividual individual, OWLDataFactory dataFactory, OWLOntology o, OWLOntologyManager man, float valor) {
			
			float value = 0;
			PrefixManager pm = new DefaultPrefixManager(baseO + "#");
			OWLDataProperty sv = dataFactory.getOWLDataProperty(":suspicious_value", pm);
			if (sv!=null &&  individual!=null) {
					Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
					for (OWLDataPropertyAssertionAxiom ax : properties) {
						if (ax.getProperty().equals(sv) && ax.getSubject().equals(individual)) {
							String svalue = ax.getObject().getLiteral();
							value = Float.parseFloat(svalue);
							man.removeAxiom(o, ax);
						}	
					}
			}
			
			valor = value+valor;
			
			OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(sv, individual, valor);
			man.addAxiom(o, dAxiom);
			 
			
		 }
		 
		 public void updateSuspiciousValue(OWLDataFactory dataFactory, OWLOntology o, OWLOntologyManager man) {
			Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
			 for(OWLNamedIndividual i:instances) {
				 System.out.println(i);
				 System.out.println(i.getClass());
			 }
		 }
		
}
