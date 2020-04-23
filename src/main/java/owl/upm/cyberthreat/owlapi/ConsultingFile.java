package owl.upm.cyberthreat.owlapi;

import java.io.*;
import java.util.*;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;


public class ConsultingFile extends Thread{
	
	
	private Anomaly anomaly;
	String base;
	OWLDataFactory dataFactory;
	OWLOntologyManager man;
	OWLOntology o_tmp;

	
	public ConsultingFile(String filename, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLOntology o) throws IOException, ParseException {
		
	}

	

	// Constructor, getter y setter

	public void procesarFichero(OntologyApp oApp, long timeStamp) {

		System.out.println("Procesando ficheroJSONSensores.json");

	}


	private void esperarXsegundos(int segundos) {
		try {
			Thread.sleep(segundos * 1000);
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}
	

}
