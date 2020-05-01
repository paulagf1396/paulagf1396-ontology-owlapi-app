package owl.upm.cyberthreat.owlapi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.json.simple.JSONObject;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot3D;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.util.Rotation;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Test;
import org.mindswap.pellet.PelletOptions;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.FunctionalSyntaxDocumentFormat;
import org.semanticweb.owlapi.formats.PrefixDocumentFormat;
import org.semanticweb.owlapi.io.SystemOutDocumentTarget;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataAllValuesFrom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataRange;
import org.semanticweb.owlapi.model.OWLEntity;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLLiteral;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLObjectPropertyExpression;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyIRIMapper;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.OWLSignature;
import org.semanticweb.owlapi.model.OWLSubClassOfAxiom;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.InferenceType;
import org.semanticweb.owlapi.reasoner.Node;
import org.semanticweb.owlapi.reasoner.NodeSet;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerConfiguration;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.reasoner.ReasonerProgressMonitor;
import org.semanticweb.owlapi.reasoner.SimpleConfiguration;
import org.semanticweb.owlapi.reasoner.impl.OWLClassNode;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.util.InferredAxiomGenerator;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;
import org.semanticweb.owlapi.util.InferredSubClassAxiomGenerator;
import org.semanticweb.owlapi.util.PriorityCollection;
import org.semanticweb.owlapi.util.Version;
import org.swrlapi.core.SWRLAPIRule;
import org.swrlapi.core.SWRLRuleEngine;
import org.swrlapi.exceptions.SWRLBuiltInException;
import org.swrlapi.factory.SWRLAPIFactory;
import org.swrlapi.parser.SWRLParseException;

import com.clarkparsia.pellet.owlapiv3.PelletReasoner;
import com.clarkparsia.pellet.owlapiv3.PelletReasonerFactory;
import com.google.common.base.Optional;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;



public class OntologyApp {


	private static int loadedAnomalyInstances;
	private static Anomaly anomaly;
	private static DRM drm;
	private static STIX stix;
	public static  Map<String, Float> dataset;
	private static Chart chart;	
	private static String pathAnomaliesFile = "./owl-files/ficheroJSONSensores.json";
	private static String pathSTIXFile = "./owl-files/ficheroJSONSTIX.json";

	 
	public OntologyApp() {
	
	}
	private static void saveOntologyinFile(OWLOntologyManager man, OWLOntology o) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		
		File fileout = new File("./owl-files/example0.owl");
		man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		System.out.println("Saving ontology...");
		
	}
	
	
	/*************************************************************/
    /**                                                         **/
    /**              Load New Instances                         **/
    /**                                                         **/
    /*************************************************************/
	 
	public int loadAnomaliesFromBBDD (OWLOntology o, OWLOntologyManager man, File filename, String base, OWLDataFactory dataFactory) throws IOException, ParseException, OWLOntologyStorageException {
		
		int numInstances = 0;
		//if the file is empty, returns 0	
		if(filename.toString().isEmpty()) {
			return 0;
		}
		
		filename  = copyFile(filename);

		JSONParser jsonParser = new JSONParser();
		System.out.println("loading JSON file...\n");
		FileReader reader = new FileReader(filename);

		//loadinf JSONObject...
		Object obj = jsonParser.parse(reader);
		//Loading JSONArray
		JSONArray dataList = (JSONArray) obj;
		System.out.println("JSONObject List obtained from file:\n");
        System.out.println(dataList);
        
        //The instances are loaded to the corresponding class
        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject jObject = (JSONObject) dataList.get(i); 
        	if(jObject.get("anomaly").toString().equals("1") ) {
        		//If anomaly=1 means that there has been an anomaly. 0 means there hasnt been any.
        		//String id = jObject.get("id").toString();
        		//OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+"Anomalia"+id));
        		anomaly.loadAnomalyInstances(man,o, dataFactory, jObject);
        		
        		numInstances++;
        	}else {
        		//Amenazas y Riesgos
        	}
        	
        }
        reader.close();
        man.saveOntology(o);
        deleteFile(filename);
        return numInstances;
		
	}

public int loadSTIXInstances (OWLOntology o, OWLOntologyManager man, File filename, String base, OWLDataFactory dataFactory) throws IOException, ParseException, OWLOntologyStorageException {
		
		int numInstances = 0;
		//if the file is empty, returns 0	
		if(filename.toString().isEmpty()) {
			return 0;
		}
		
		filename  = copyFile(filename);

		JSONParser jsonParser = new JSONParser();
		System.out.println("loading JSON file...\n");
		FileReader reader = new FileReader(filename);

		//loadinf JSONObject...
		Object obj = jsonParser.parse(reader);
		//Loading JSONArray
		JSONArray dataList = (JSONArray) obj;
		System.out.println("JSONObject List obtained from file:\n");
        System.out.println(dataList);
        
        //The instances are loaded to the corresponding class
        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject jObject = (JSONObject) dataList.get(i); 
    		stix.createSTIXInstances(man,o, dataFactory, jObject);
    		numInstances++;
        
        	
        }
        reader.close();
        man.saveOntology(o);
        deleteFile(filename);
        return numInstances;
		
	}

	/*************************************************************/
    /**                                                         **/
    /**        Methods to manipulate the ontology               **/
    /**                                                         **/
    /*************************************************************/
	//Crear individuals
	/*public void createIndividuals(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String cls, String individualName, int isType) throws OWLOntologyStorageException {
		
		//Anomaly=2, DRM = 1 , STIX = 0
		
		if(isType ==0) {
			stix.createSTIXInstances(man, o, dataFactory, cls, individualName);
		}
		else if(isType==1){
			
			drm.createDRMInstances(man, o, dataFactory, cls, individualName);
			
		}else if(isType==2){
			anomaly.createAnomalyInstances(man, o, dataFactory, cls, individualName);
		}else {
			System.out.println("The ontology type selected does not exist");
		}
		man.saveOntology(o);
	}*/
	
	//Crear Data Properties
	public void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String object, String property, String value) {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		
		OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":"+property, pm);
		OWLIndividual instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object));
		OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, instance, value);
		man.addAxiom(o, dAxiom);
	}
	
	//Crear Object Properties
	public void createObjectProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String object1, String object2, String property) {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		
		OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":"+property, pm);
		OWLIndividual instance1 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object1));
		OWLIndividual instance2 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object2));

		OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, instance1, instance2);
		man.addAxiom(o, oAxiom);
	}
	
	/*************************************************************/
    /**                                                         **/
    /**                         Reasoner                        **/
    /**                                                         **/
    /*************************************************************/
	//Load Pellet Reasoner
	public void loadReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) throws OWLOntologyStorageException {
		
		
		//System.out.println(PelletOptions.IGNORE_UNSUPPORTED_AXIOMS);
		//PelletOptions.IGNORE_UNSUPPORTED_AXIOMS = false;
		//System.out.println(PelletOptions.IGNORE_UNSUPPORTED_AXIOMS);
		
		System.out.println("Using reasoner: "+ reasoner.getReasonerName());
		System.out.println("The ontology consistency is "+reasoner.isConsistent());
		
		//System.out.println("Executing rules...");
		//reasoner.getKB().realize();
		//reasoner.precomputeInferences();
		//System.out.println("**********************Class tree**********************");
		//reasoner.getKB().printClassTree();
		//System.out.println("******************************************************");
		System.out.println("Loading infered axioms to the ontology...");
		loadInferedAxiomsByReasoner(o, man, dataFactory, base, reasoner);
		System.out.println("Done.");
		
		//System.out.println("Dynamic Risk Calculation");
		//dynamicRiskCalculation(o, man, dataFactory, base, reasoner);
		

	}
	public void loadInferedAxiomsByReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) throws OWLOntologyStorageException {

		//What was inferred is written to the ontology
        List<InferredAxiomGenerator<? extends OWLAxiom>> gens = new ArrayList<InferredAxiomGenerator<? extends OWLAxiom>>();
        gens.add(new InferredSubClassAxiomGenerator());

        //Create the inferred ontology generator
        InferredOntologyGenerator iog = new InferredOntologyGenerator(reasoner, gens);
        iog.fillOntology(dataFactory, o);

        man.saveOntology(o);
        
	}
	
	
	
	

	
	/*************************************************************/
    /**                                                         **/
    /**                     Rules Engine                        **/
    /**                                                         **/
    /*************************************************************/
	
	//Load SWRL rules engine
	public void loadSWRLRuleENgine(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
	 
		 // Run the SWRL rules in the ontology
		// swrlRuleEngine.infer();
		float umbral = 5;
		//Threat Inventory
		swrlRuleEngine.createSWRLRule("Anomalies#1 Suspicious Value Umbral Wifi","cyberthreat_ONA:WiFi_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w)");
		swrlRuleEngine.createSWRLRule("Anomalies#2 Suspicious Value Umbral Bluetooth","cyberthreat_ONA:Bluetooth_Sensor_Anomaly(?b) ^ cibersituational-ontology:suspicious_value(?b, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?b) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?b)");
		swrlRuleEngine.createSWRLRule("Anomalies#3 Suspicious Value Umbral RF","cyberthreat_ONA:RF_Sensor_Anomaly(?rf) ^ cibersituational-ontology:suspicious_value(?rf, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?rf) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DenialOfService(?x) ^ cibersituational-ontology:type(?x, \"Threat Denial of Service\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?rf)");

		//Risk Inventory
		swrlRuleEngine.createSWRLRule("RiskInventory#4 Wifi Anomaly + Threat", "cyberthreat_ONA:WiFi_Sensor_Anomaly(?w) ^ cibersituational-ontology:probability(?x, ?p) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, ?i) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ swrlx:makeOWLThing(?r, ?x) -> cyberthreat_DRM:DeliberatedUnauthorizedAccessRisk(?r) ^ cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:type(?r, \"Deliberated Unauthorized Access Risk\")");

		
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		 swrlRuleEngine = null;
		 
	}
	
		
	//Infer
	public void inferSWRLEngine(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
	 
		 // Run the SWRL rules in the ontology
		 swrlRuleEngine.infer();
		
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		 swrlRuleEngine = null;
		 System.out.println("Ontology saved.");
	}

		
	
	/*************************************************************/
    /**                                                         **/
    /**              	Additional Methods                      **/
    /**                                                         **/
    /*************************************************************/
	

	
	// Metodo para crear el archivo de copia de la ontologia
	@SuppressWarnings("resource")
	public static File copyFile(File sourceFile) throws IOException {
		String jsonAux = "./owl-files/ficheroJSONSensoresAux.json";
		File destFile = new File(jsonAux);
		
		if (destFile.exists()) {
			destFile.delete();
		}
		destFile.createNewFile();

		FileChannel source = null;
		FileChannel destination = null;
		try {
			source = new RandomAccessFile(sourceFile, "rw").getChannel();
			destination = new RandomAccessFile(destFile, "rw").getChannel();

			long position = 0;
			long count = source.size();

			source.transferTo(position, count, destination);
		} finally {
			if (source != null) {
				source.close();
			}
			if (destination != null) {
				destination.close();
			}
		}
		//Vacia el ficheroJSONSensores donde se vanescribiendo las nuevas anomalias
		new PrintWriter(sourceFile).close();
		return destFile;
	}
	//To delete a file
	public void deleteFile(File file) throws IOException {
		File fileDestination = file;
		try {
			Files.delete(fileDestination.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	
	public boolean isEmptyAnomaliesFile(File filename ) throws IOException, ParseException{
		//if the file is empty, returns 0	
		
		boolean updated = false;

		JSONParser jsonParser = new JSONParser();
		System.out.println("loading JSON file...\n");
		FileReader reader = new FileReader(filename);
		System.out.println(filename.length()==0);
		if (filename.length()==0) {
        	updated=false;
        	
        	System.out.println("There hasn't any new anomaly");
        	
        }else {
        	//loading JSONObject...
    		Object obj = jsonParser.parse(reader);
    		//Loading JSONArray
    		JSONArray dataList = (JSONArray) obj;
    		System.out.println("JSONObject List obtained from file:\n");
            System.out.println(dataList);
            
            //The instances are loaded to the corresponding class
            //No cambia
            if (dataList.size()==0) {
            	updated=false;
            	System.out.println(dataList.isEmpty());
            	System.out.println("There hasn't any new anomaly");
            	
            }
            //Se han añadido nuevos
            else if(dataList.size() > 0) {
            	updated = true; 
            	
            }
        }
		
		
       reader.close();
       return updated;
		
	}
	
	 public boolean updateSuspiciousValue(OWLDataFactory dataFactory, OWLOntology o, OWLOntologyManager man, OWLReasoner reasoner, String base) throws OWLOntologyStorageException {
		 	PrefixManager pm = new DefaultPrefixManager(base + "#");
		 	
		 	boolean done = false;
			Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
			 for(OWLNamedIndividual i:instances) {
				 System.out.println(i);
				 NodeSet<OWLNamedIndividual> wset = reasoner.getInstances(Anomaly.getWifi_sensor_anomaly(), true) ;
				 for(OWLNamedIndividual winstance : wset.getFlattened()) {
					 OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":related-to", pm);	
					 String mac1 = anomaly.obtainObjectPropertyValue(winstance, oproperty, o, reasoner);
					 String mac2 = anomaly.obtainObjectPropertyValue(i, oproperty, o, reasoner);
					 if(mac1 != null && mac2 !=null && mac1.equals(mac2)) {
						 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, 1);
						 done=true;
					 }
					 
				 }
				 NodeSet<OWLNamedIndividual> btset = reasoner.getInstances(Anomaly.getBt_sensor_anomaly(), true) ;
				 for(OWLNamedIndividual btinstance : btset.getFlattened()) {
					 OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":related-to", pm);	
					 String mac1 = anomaly.obtainObjectPropertyValue(btinstance, oproperty, o, reasoner);
					 String mac2 = anomaly.obtainObjectPropertyValue(i, oproperty, o, reasoner);
					 if(mac1 != null && mac2 !=null && mac1.equals(mac2)) {
						 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, 1);
						 done = true;
					 }
					 
				 }
				 
				 NodeSet<OWLNamedIndividual> rfset = reasoner.getInstances(Anomaly.getRf_sensor_anomaly(), true) ;
				 for(OWLNamedIndividual rfinstance : rfset.getFlattened()) {
					 OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_signal_frequency", pm);	
					 String mac1 = anomaly.obtainDataPropertyValue(rfinstance, dproperty, o, reasoner);
					 String mac2 = anomaly.obtainDataPropertyValue(i, dproperty, o, reasoner);
					 if(mac1 != null && mac2 !=null && mac1.equals(mac2)) {
						 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, 1);
						 done = true;
					 }
					 
				 }
			 }
			 man.saveOntology(o);
			 return done;
		 }
	 
	
	public static void main(String[] args) throws OWLOntologyCreationException, IOException, ParseException, SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		OntologyApp onto_object =new OntologyApp();
		
		OWLOntology o = null;
		String base = null;
		
		//Ontology files are loaded, copy and original
		System.out.println("");
		System.out.println("Loading Ontology...");
		File file = new File("./owl-files/cibersituational-ontov2.owl");
		File fileTmp = new File("./owl-files/cibersituational-ontov2-tmp.owl");

		
		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		o =  man.loadOntologyFromOntologyDocument(fileTmp);
		OWLDataFactory dataFactory = man.getOWLDataFactory();
		IRI documentIRI = o.getOntologyID().getOntologyIRI().get();
		base = documentIRI.toString();
		System.out.println("Ontology loaded\n");
	
		
		anomaly = new Anomaly(dataFactory, man, base);
		drm = new DRM(dataFactory, man, base);
		stix = new STIX(dataFactory, man, base);
		

		// CARGAR ACTIVOS
		
		//Load rules
		System.out.println("Loading rules...\n");
		onto_object.loadSWRLRuleENgine(o, man, dataFactory, base);
		System.out.println("Rules loaded.\n");
		
		//Copy in other ontology
		//File fileAnom = copyFile(fileTmp);
		//OWLOntology o2 = null;
		//IRI iri = null;
		//OWLOntologyManager man2 = OWLManager.createOWLOntologyManager();
		//OWLDataFactory dataFactory2 = man2.getOWLDataFactory();
		//o2= man2.loadOntologyFromOntologyDocument(fileAnom);
		//iri = o2.getOntologyID().getOntologyIRI().get();
		//String base2 = iri.toString();
		
		
		//File to load information
		System.out.println("Loading data from BBDD into the ontology...\n");
		boolean updated = false;
		File ficheroJSONSensores = new File(pathAnomaliesFile);
		updated = onto_object.isEmptyAnomaliesFile(ficheroJSONSensores);
		if(updated) {
			//se crcea nueva ontologia copiando las anomalias y sustituye la o actual por otra
			loadedAnomalyInstances = onto_object.loadAnomaliesFromBBDD(o, man, ficheroJSONSensores, base, dataFactory);
			System.out.println("There have been loaded "+loadedAnomalyInstances+ " instances of new anomalies\n");
			updated = false;
		}else {
			System.out.println("There are no new anomalies");
		}
		
		
		//Load STIX elements
		//File to load information
		System.out.println("Loading STIX data into the ontology...\n");
		boolean updatedSTIX = false;
		File ficheroJSONSTIX = new File(pathSTIXFile);
		updatedSTIX = onto_object.isEmptyAnomaliesFile(ficheroJSONSTIX);
		if(updatedSTIX) {
			//se crcea nueva ontologia copiando las anomalias y sustituye la o actual por otra
			int loadedSTIXInstances=0;
			loadedSTIXInstances = onto_object.loadSTIXInstances(o, man, ficheroJSONSTIX, base, dataFactory);
			System.out.println("There have been loaded "+loadedSTIXInstances+ " instances of STIX\n");
			updatedSTIX = false;
		}else {
			System.out.println("There are no new stix elements");
		}
		
		
		//Razona sobre la nueva ontologia, ejecuto reglas 1 vez
		
		//Cargar razonador
		System.out.println("Starting the reasoner...\n");
		OWLReasonerFactory reasonerFactory = PelletReasonerFactory.getInstance();
		PelletReasoner reasoner =  (PelletReasoner) reasonerFactory.createReasoner(o);
		reasoner.precomputeInferences(InferenceType.DATA_PROPERTY_ASSERTIONS);
		onto_object.loadReasoner(o, man, dataFactory, base, reasoner);
		
		//Execute rules
		System.out.println("Infering from rules...\n");
		onto_object.inferSWRLEngine(o, man, dataFactory, base);
		System.out.println("Done.\n");
		
		//deberia calcularme el riesgo y sacar grafica

		//Me guardo todo y 
		while(true) {
			

			System.out.println("Checking if there are new anomalies...\n");
			updated = onto_object.isEmptyAnomaliesFile(ficheroJSONSensores);	
			if(updated) {
				loadedAnomalyInstances = onto_object.loadAnomaliesFromBBDD(o, man, ficheroJSONSensores, base, dataFactory);
				System.out.println("There have been loaded "+loadedAnomalyInstances+ " instances of new anomalies\n");
				updated = false;
				System.out.println("Updated SUSPICIOUS VALUE "+onto_object.updateSuspiciousValue(dataFactory, o, man, reasoner, base));
				break;
				//onto_object.loadNewRule(o, man, anomaly);
			}
				
			try {
				Thread.sleep(5000);
			
			} catch (InterruptedException e) {
				e.printStackTrace();
			}			
		}
		onto_object.loadReasoner(o, man, dataFactory, base, reasoner);
		System.out.println("Infering from rules...\n");
		onto_object.inferSWRLEngine(o, man, dataFactory, base);
		System.out.println("Done.\n");
		
		
		Risk r = new Risk();
		Map<String, Float> dataRRisk = new HashMap<String, Float>();
		dataRRisk = r.residualRiskCalculation(o, man, dataFactory, base, reasoner, drm.base);
		Map<String, Float> dataPRisk = new HashMap<String, Float>();
		dataPRisk = r.potentialRiskCalculation(o, man, dataFactory, base, reasoner, drm.base);
		chart = new Chart(dataRRisk,dataPRisk );
		chart.barchartPaint("Residual Risk", "Potential Risk");
		
		
		//Verificar si es necesario modificar el sv value porque haya anomalias referentes al mismo sitio
		//razonar
		//caluclar riesgo
		//Esperar mas anomalias
		
		//Cargar razonador
		//System.out.println("Starting the reasoner...\n");
		//onto_object.loadReasoner(o, man, dataFactory, base);
		
		

		
		
	}

}
