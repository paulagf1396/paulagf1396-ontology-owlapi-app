package owl.upm.cyberthreat.owlapi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.FunctionalSyntaxDocumentFormat;
import org.semanticweb.owlapi.io.SystemOutDocumentTarget;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLEntity;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.OWLSignature;
import org.semanticweb.owlapi.model.OWLSubClassOfAxiom;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OntologyApp {

	private static String base;
	private static IRI documentIRI;
	private static int loadedAnomalyInstances;
	
	private static void saveOntologyinFile(OWLOntologyManager man, OWLOntology o) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		
		File fileout = new File("./owl-files/example0.owl");
		man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		System.out.println("Saving ontology...");
	}
	
	 
	public int loadAnomaliesFromBBDD (OWLOntology o, OWLOntologyManager man, String fileAnomaliesJSON, String base) throws IOException, ParseException {
		OWLDataFactory dataFactory = man.getOWLDataFactory();
		int numInstances = 0;
		//Si el fichero esta vacío	
		if(fileAnomaliesJSON.isEmpty()) {
			return 0;
		}
		
		JSONParser jsonParser = new JSONParser();
		System.out.println("cargando fichero JSON ...");
		FileReader reader = new FileReader("./owl-files/ficheroJSONSensores.json");

		//cargando objeto json...
		Object obj = jsonParser.parse(reader);
		//Cogiendo JSONArray
		JSONArray dataList = (JSONArray) obj;
		System.out.println("LISTA DE OBJETOS JSON");
        System.out.println(dataList);
        
        //Se anaden las instancias a la clase correspondiente
        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject jObject = (JSONObject) dataList.get(i);
        
        	if(jObject.get("anomaly").toString().equals("1") ) {
       
        		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+"Anomalia"+i));
        		loadAnomalyInstances(man,anomaly_instance,o, dataFactory, jObject);	
        		numInstances++;
        		
        	}else {
        		//Amenazas y Riesgos
        	}
        	
        }
        reader.close();
        return numInstances;
		
	}
	
	private static void  loadAnomalyInstances (OWLOntologyManager man, OWLIndividual anomaly_instance, OWLOntology o, OWLDataFactory dataFactory, JSONObject anomaly) {
		//Classes from Anmoaly Ontology
		OWLClass wifi_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"WiFi_Sensor_Anomaly");
		OWLClass uba_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"UBA_Sensor_Anomaly");
		OWLClass rm_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"RM_Sensor_Anomaly");
		OWLClass rf_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"RF_Sensor_Anomaly");
		OWLClass ids_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"Cybersecurity_Sensor_Anomaly");
		OWLClass bt_sensor_anomaly = dataFactory.getOWLClass(base +"#"+"Bluetooth_Sensor_Anomaly");
		OWLClass event = dataFactory.getOWLClass(base +"#"+"Event");
		
		String type = anomaly.get("type").toString();
		if(type.equals("WiFi")) {
			
			OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(wifi_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma0);

			//Si existe evento lo anado
			if(!anomaly.get("event").toString().isEmpty()) {
				OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(base +"#"+"caused_by");
				String event_wifiAnomaly = anomaly.get("event").toString();
	    		OWLIndividual event_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+event_wifiAnomaly));
	    		OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(event, event_instance);
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, anomaly_instance, event_instance);
				man.addAxiom(o, axioma1);
				man.addAxiom(o, oAxiom);
			}
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
		else if(type.equals("Bluetooth")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(bt_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
		else if(type.equals("IDS")){
			OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(ids_sensor_anomaly, anomaly_instance);
			man.addAxiom(o, axioma);
		}
    	System.out.println(anomaly_instance);
		
		
	}
	
	public void loadReasoner(OWLOntology o, OWLOntologyManager man,OWLDataFactory dataFactory ) {
		
		
	}
	
	public static void main(String[] args) throws OWLOntologyCreationException, IOException, ParseException {
		OntologyApp onto_object =new OntologyApp();
		
		System.out.println("");
		System.out.println("Loading Ontology...");
		File file = new File("./owl-files/cyberthreat_ONA.owl");
		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		
		OWLOntology o =  man.loadOntologyFromOntologyDocument(file);
		documentIRI = o.getOntologyID().getOntologyIRI().get();
		base = documentIRI.toString();
		System.out.println(base);
		
		//File to load information
		File fileAnomalies = new File("./owl-files/ficheroJSONSensores.json");
		String fileAnomaliesJSON = fileAnomalies.toString();
		loadedAnomalyInstances = onto_object.loadAnomaliesFromBBDD(o, man, fileAnomaliesJSON, base);
		System.out.println(loadedAnomalyInstances);
	
		
	}

}
