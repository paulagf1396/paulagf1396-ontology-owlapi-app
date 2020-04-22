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
	
	private JSONArray dataList;
	private Anomaly anomaly;
	String base;
	OWLDataFactory dataFactory;
	OWLOntologyManager man;
	OWLOntology o_tmp;

	
	public ConsultingFile(String filename, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLOntology o) throws IOException, ParseException {
		dataList = initializationJSON(filename);
		anomaly = new Anomaly(dataFactory, man, base);
		this.dataFactory = dataFactory;
		this.man = man;
		o_tmp = o;
		this.base = base;
	}
	
	public JSONArray initializationJSON(String filename) throws IOException, ParseException {
		
		JSONParser jsonParser = new JSONParser();
		FileReader reader = new FileReader(filename);
		Object obj = jsonParser.parse(reader);
		JSONArray jarray= (JSONArray) obj;
		int numInstances=0;
		for(int i = 0; i< jarray.size(); i++) {
        	JSONObject jObject = (JSONObject) jarray.get(i); 
        	System.out.println("Anomalia"+i+ "\n");
        	System.out.println(jObject.get("anomaly").toString());
        	
      //  	OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.base +"#"+"Anomalia"+i));
    		anomaly.loadAnomalyInstances(man,anomaly_instance,o_tmp, dataFactory, jObject);	
        	
        	numInstances++;
        }
		System.out.println("Se han añadido "+numInstances+" anomalias");
		reader.close();
		return jarray;
		
	}
	
	public boolean updateAnomalies(File fileAnomaliesJSON ) throws IOException, ParseException{
		//if the file is empty, returns 0	
		boolean newanomaly = false;
		if(fileAnomaliesJSON.toString().isEmpty()) {
			System.out.println("The file is empty");
			return newanomaly;
		}		

		JSONParser jsonParser = new JSONParser();
		System.out.println("loading JSON file...\n");
		FileReader reader = new FileReader(fileAnomaliesJSON);

		//loading JSONObject...
		Object obj = jsonParser.parse(reader);
		//Loading JSONArray
		JSONArray dataList2 = (JSONArray) obj;
		System.out.println("JSONObject List obtained from file:\n");
        System.out.println(dataList2);
        
        //The instances are loaded to the corresponding class
        //No cambia
        if (dataList2.size() == dataList.size()) {
        	newanomaly=false;
        	System.out.println("There hasn't any new anomaly");
        	
        }
        //Se han añadido nuevos
        else if(dataList2.size() > dataList.size()) {
        	newanomaly = true;
        	int nuevas = dataList2.size() - dataList.size();
        	System.out.println("There has been "+nuevas+" new anomalies");
        	
        	//Dice que hay nuevas pero no las mete
        	for(int i = dataList.size(); i< dataList2.size(); i++) {
            	JSONObject jObject = (JSONObject) dataList2.get(i); 
            	System.out.println("Anomalia"+i+ "\n");
            	System.out.println(jObject.get("anomaly").toString());
            	
            }
        	//actualiza el fichero de anomalias
        	dataList = dataList2;
        		
        	
        }else if(dataList2.isEmpty()){
        	newanomaly=false;
        	System.out.println("There aren't anomalies, EMPTY FILE");
        	
        }
       reader.close();
       return newanomaly;
		
	}
	
	public boolean consultFileModification(File filename, boolean update) throws IOException, InterruptedException, ParseException {
		
		boolean flaganomaly=false;
		BufferedReader reader = new BufferedReader(new FileReader(filename));

		String line = "";
		while (update) {
		    line = reader.readLine();
		    if (line == null) {
		    	Thread.sleep(5000);
		    }
		    else {

		    	flaganomaly= updateAnomalies(filename);

		    }
		}
		return flaganomaly;
		
	}
	
	
	 public void run() {
		long time = 5000;
        while(true) {
          //execute your code
           try {
        	
			Thread.sleep(time);
		
           
           
           } catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        }
	 }
	

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
