package owl.upm.cyberthreat.owlapi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.FunctionalSyntaxDocumentFormat;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OntologyApp {

	private static String base;
	private static IRI documentIRI;
	
	private static void saveOntologyinFile(OWLOntologyManager man, OWLOntology o) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		
		File fileout = new File("./owl-files/example0.owl");
		man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		System.out.println("Saving ontology...");
	}
	
	 
	
	public int loadAnomaliesFromBBDD (OWLOntology o, OWLOntologyManager man, String fileAnomaliesJSON, String base) throws IOException, ParseException {
		 OWLDataFactory factory = man.getOWLDataFactory();
		
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
        System.out.println(dataList);
        
        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject anomaly = (JSONObject) dataList.get(i);
        	OWLIndividual anomaly_instance = factory.getOWLNamedIndividual(IRI.create(base +"#"+"Anomalia"+i));
        	System.out.println(anomaly_instance);
        }
    
        

        reader.close();
        return 1;
		
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
		onto_object.loadAnomaliesFromBBDD(o, man, fileAnomaliesJSON, base);
	
	}

}
