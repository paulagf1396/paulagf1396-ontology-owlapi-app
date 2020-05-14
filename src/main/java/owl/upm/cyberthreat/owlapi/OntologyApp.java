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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.json.simple.JSONObject;
import org.apache.commons.lang3.StringUtils;
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
import org.semanticweb.owlapi.model.AxiomType;
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
import org.semanticweb.owlapi.util.OWLEntityRemover;
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
	private static String pathAnomaliesFile = Configuration.getPath().get("ficheroJSONSensores");
	private static String pathSTIXFile = Configuration.getPath().get("ficheroJSONSTIX");
	
	Map<String, Float> amenazasReales = new HashMap<String, Float>();
	
	public static double numeroAmenazasPorRiesgo[];
	
	
	

	 
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
	
	public static void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object, OWLDataProperty dproperty, Double value) {

		if (dproperty!=null &&  object!=null && value!=null) {
			Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(object);
			for (OWLDataPropertyAssertionAxiom ax : properties) {
				if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(object)) {
					man.removeAxiom(o, ax);
				}	
			}
			
			OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, value);
			man.addAxiom(o, dAxiom);
		}else {
			System.out.println("Not properly data to create Data Property");
		}
		
		
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
		reasoner.precomputeInferences();
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
	public void loadSWRLRulesAnomaliesThreatsAndRisks(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
	 
		 // Run the SWRL rules in the ontology
		// swrlRuleEngine.infer();
		float umbral = Configuration.umbral;
		//Threat Inventory
		//swrlRuleEngine.createSWRLRule("Anomalies#1 Suspicious Value Umbral Wifi","cyberthreat_ONA:WiFi_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w)^ cibersituational-ontology:numType(?x, 14)");
		//swrlRuleEngine.createSWRLRule("Anomalies#2 Suspicious Value Umbral Bluetooth","cyberthreat_ONA:Bluetooth_Sensor_Anomaly(?b) ^ cibersituational-ontology:suspicious_value(?b, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?b) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?b) ^ cibersituational-ontology:numType(?x, 14)");
		//swrlRuleEngine.createSWRLRule("Anomalies#3 Suspicious Value Umbral RF","cyberthreat_ONA:RF_Sensor_Anomaly(?rf) ^ cibersituational-ontology:suspicious_value(?rf, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?rf) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DenialOfService(?x) ^ cibersituational-ontology:type(?x, \"Threat Denial of Service\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?rf)^ cibersituational-ontology:numType(?x, 15)");
		swrlRuleEngine.createSWRLRule("Anomalies1", "cyberthreat_ONA:WiFi_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w) ^ cibersituational-ontology:numType(?x, 14)");
		swrlRuleEngine.createSWRLRule("Anomalies2", "cyberthreat_ONA:Bluetooth_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w) ^ cibersituational-ontology:numType(?x, 14)");
		swrlRuleEngine.createSWRLRule("Anomalies3", "cyberthreat_ONA:RF_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DenialOfService(?x) ^ cibersituational-ontology:type(?x, \"Threat Denial Of Service\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w) ^ cibersituational-ontology:numType(?x, 15)");
		swrlRuleEngine.createSWRLRule("Anomalies4", "cyberthreat_ONA:RM_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w) ^ cibersituational-ontology:numType(?x, 14)");
		swrlRuleEngine.createSWRLRule("Anomalies5", "cyberthreat_ONA:Cybersecurity_Sensor_Anomaly(?w) ^ cibersituational-ontology:suspicious_value(?w, ?s) ^ swrlb:greaterThanOrEqual(?s, "+umbral+") ^ swrlx:makeOWLThing(?x, ?w) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:DenialOfService(?x) ^ cibersituational-ontology:type(?x, \"Threat Denial Of Service\") ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_STIXDRM:isGeneratedBy(?x, ?w) ^ cibersituational-ontology:numType(?x, 15)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#1 Auto Bad Reputation Threat in Classified Data", "swrlx:makeOWLThing(?x, ?classified_data) ^ cyberthreat_DRM:ClassifiedData(?classified_data) ^ cyberthreat_DRM:dependsOn(?rs, ?classified_data) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:Asset_Valuation(?av) -> cibersituational-ontology:probability(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:BadReputationThreat(?x) ^ cibersituational-ontology:type(?x, \"Threat Bad Reputation\"^^rdf:PlainLiteral) ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_DRM:threatens(?x, ?classified_data) ^ cibersituational-ontology:numType(?x, 1)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#2 Auto Data Protection Threat", "cyberthreat_DRM:Asset_Valuation(?av) ^ cyberthreat_DRM:dependsOn(?rs, ?classified_data) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:ClassifiedData(?classified_data) ^ swrlx:makeOWLThing(?x, ?classified_data) -> cyberthreat_DRM:threatens(?x, ?classified_data) ^ cibersituational-ontology:impact(?x, \"7.0\"^^xsd:float) ^ cyberthreat_DRM:DataProtectionRisks(?x) ^ cibersituational-ontology:probability(?x, \"3.0\"^^xsd:float) ^ cibersituational-ontology:type(?x, \"Threat against Data Protection\"^^rdf:PlainLiteral) ^ cibersituational-ontology:numType(?x, 5)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#3 Auto Unintentional User Error Threat", "cyberthreat_DRM:Users(?u) ^ swrlb:lessThanOrEqual(?e, 3) ^ swrlx:makeOWLThing(?x, ?u) ^ cyberthreat_DRM:dependsOn(?rs, ?new_data) ^ cyberthreat_DRM:dependsOn(?new_data, ?hw) ^ cibersituational-ontology:has_cybersecurity_experience(?u, ?e) ^ cyberthreat_DRM:dependsOn(?hw, ?u) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:Hardware(?hw) ^ cyberthreat_DRM:Asset_Valuation(?av) ^ cyberthreat_DRM:Data(?new_data) -> cibersituational-ontology:probability(?x, \"3.0\"^^xsd:float) ^ cibersituational-ontology:impact(?x, \"3.0\"^^xsd:float) ^ cibersituational-ontology:type(?x, \"Threat Unintentional User Error\"^^rdf:PlainLiteral) ^ cyberthreat_DRM:threatens(?x, ?u) ^ cyberthreat_DRM:NonIntentionalUserError(?x)^ cibersituational-ontology:numType(?x, 31)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#4 Auto SW Vulnerabilities Threat", "swrlx:makeOWLThing(?x, ?sw) ^ cyberthreat_DRM:Data(?new_data) ^ cyberthreat_DRM:dependsOn(?rs, ?new_data) ^ cyberthreat_DRM:Software(?sw) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:dependsOn(?new_data, ?sw) ^ cyberthreat_DRM:Asset_Valuation(?av) -> cyberthreat_DRM:SWVulnerabilities(?x) ^ cibersituational-ontology:probability(?x, \"4.0\"^^xsd:float) ^ cibersituational-ontology:type(?x, \"Threat SW Vulnerabilities\"^^rdf:PlainLiteral) ^ cibersituational-ontology:impact(?x, \"2.0\"^^xsd:float) ^ cyberthreat_DRM:threatens(?x, ?sw)^ cibersituational-ontology:numType(?x, 39)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#5 Auto Deliberated Malicious SW Distribution Threat", "cyberthreat_DRM:Users(?u) ^ swrlb:lessThanOrEqual(?e, 3) ^ cyberthreat_DRM:dependsOn(?rs, ?new_data) ^ cibersituational-ontology:has_cybersecurity_experience(?u, ?e) ^ cyberthreat_DRM:dependsOn(?new_data, ?sw) ^ cyberthreat_DRM:dependsOn(?new_data, ?u) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:Asset_Valuation(?av) ^ cyberthreat_DRM:Software(?sw) ^ swrlx:makeOWLThing(?x, ?sw) ^ cyberthreat_DRM:Data(?new_data) -> cibersituational-ontology:type(?x, \"Threat Deliberated Malicious SW Distribution\"^^rdf:PlainLiteral) ^ cibersituational-ontology:probability(?x, \"4.0\"^^xsd:float) ^ cyberthreat_DRM:DeliberatedMaliciousSWDistribution(?x) ^ cibersituational-ontology:impact(?x, \"3.0\"^^xsd:float) ^ cyberthreat_DRM:threatens(?x, ?sw)^ cibersituational-ontology:numType(?x, 11)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#6 Auto Social Engineering Threat", "swrlx:makeOWLThing(?x, ?u) ^ swrlb:lessThanOrEqual(?e, 3) ^ cyberthreat_DRM:Users(?u) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:ClassifiedData(?classified_data) ^ cibersituational-ontology:has_cybersecurity_experience(?u, ?e) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:dependsOn(?rs, ?classified_data) ^ cyberthreat_DRM:Asset_Valuation(?av) ^ cyberthreat_DRM:dependsOn(?classified_data, ?u) -> cyberthreat_DRM:SocialEngineering(?x) ^ cibersituational-ontology:type(?x, \"Threat Social Engineering\"^^rdf:PlainLiteral) ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cyberthreat_DRM:threatens(?x, ?u) ^ cibersituational-ontology:probability(?x, \"3.0\"^^xsd:float)^ cibersituational-ontology:numType(?x, 40)");
		swrlRuleEngine.createSWRLRule("ThreatInventory#7 Auto Corporate Brand Image Damage Threat", "swrlx:makeOWLThing(?x, ?classified_data) ^ cyberthreat_DRM:evaluates(?av, ?rs) ^ cyberthreat_DRM:ClassifiedData(?classified_data) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:dependsOn(?rs, ?classified_data) ^ cyberthreat_DRM:Asset_Valuation(?av) -> cyberthreat_DRM:threatens(?x, ?classified_data) ^ cibersituational-ontology:impact(?x, \"4.0\"^^xsd:float) ^ cibersituational-ontology:probability(?x, \"1.0\"^^xsd:float) ^ cibersituational-ontology:type(?x, \"Threat for Corporate Brand Image\"^^rdf:PlainLiteral) ^ cyberthreat_DRM:CorporateBrandImageDamages(?x) ^ cibersituational-ontology:numType(?x, 4)");
		//Risk Inventory
		swrlRuleEngine.createSWRLRule("RiskInventory#1 Auto Bad Reputation Risk", "cibersituational-ontology:probability(?x, ?p) ^ cibersituational-ontology:impact(?x, ?i) ^ cyberthreat_DRM:threatens(?x, ?a) ^ cyberthreat_DRM:BadReputationThreat(?x) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ swrlx:makeOWLThing(?r, ?x) ^ cyberthreat_DRM:dependsOn(?rs, ?a) -> cyberthreat_DRM:BadReputationRisk(?r) ^ cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:type(?r, \"Bad Reputation Risk\"^^rdf:PlainLiteral) ^ cyberthreat_DRM:damages(?r, ?a)");
		swrlRuleEngine.createSWRLRule("RiskInventory#4 Wifi Anomaly + Threat", "cyberthreat_ONA:WiFi_Sensor_Anomaly(?w) ^ cibersituational-ontology:probability(?x, ?p) ^ cyberthreat_DRM:DeliberatedUnauthorizedAccess(?x) ^ cibersituational-ontology:type(?x, \"Threat Deliberated Unauthorized Access\") ^ cibersituational-ontology:impact(?x, ?i) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ swrlx:makeOWLThing(?r, ?x) -> cyberthreat_DRM:DeliberatedUnauthorizedAccessRisk(?r) ^ cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:type(?r, \"Deliberated Unauthorized Access Risk\")");
		swrlRuleEngine.createSWRLRule("RiskInventory#2 Auto Deliberated Malicious SW Distribution Risk", "cibersituational-ontology:probability(?x, ?p) ^ cyberthreat_DRM:DeliberatedMaliciousSWDistribution(?x) ^ cibersituational-ontology:impact(?x, ?i) ^ cyberthreat_DRM:threatens(?x, ?a) ^ swrlx:makeOWLThing(?r, ?x) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:dependsOn(?rs, ?a) -> cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:type(?r, \"Deliberated Malicious SW Distribution Risk\"^^rdf:PlainLiteral) ^ cyberthreat_DRM:DeliberatedMaliciousSWDistributionRisk(?r) ^ cyberthreat_DRM:damages(?r, ?a)");
		swrlRuleEngine.createSWRLRule("RiskInventory#3 Auto Data Protection Risks Risk", "cyberthreat_DRM:DataProtectionRisks(?x) ^ cibersituational-ontology:probability(?x, ?p) ^ cyberthreat_DRM:dependsOn(?rs, ?a) ^ cibersituational-ontology:impact(?x, ?i) ^ swrlx:makeOWLThing(?r, ?x) ^ cyberthreat_DRM:threatens(?x, ?a) ^ cyberthreat_DRM:Risk_Scope(?rs) -> cyberthreat_DRM:threatens(?r, ?rs) ^ cyberthreat_DRM:DataProtectionComplianceRisk(?r) ^ cibersituational-ontology:type(?r, \"Data Protection Compliance Risk\"^^rdf:PlainLiteral) ^ cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:damages(?r, ?a)");
		swrlRuleEngine.createSWRLRule("RiskInventory#5 Denial Of Service Risk", "cibersituational-ontology:probability(?x, ?p) ^ cyberthreat_DRM:DenialOfService(?x) ^ cibersituational-ontology:type(?x, \"Threat Denial Of Service\") ^ cibersituational-ontology:impact(?x, ?i) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ swrlx:makeOWLThing(?r, ?x) -> cyberthreat_DRM:DenialOfServiceRisk(?r) ^ cyberthreat_STIXDRM:isGeneratedBy(?r, ?x) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:type(?r, \"Denial of Service Risk\")");
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		 
		 
	}
	
	//Load SWRL rules engine
	public void deleteSWRLRules(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, int flag) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
		 if(flag == 0) {
			 swrlRuleEngine.deleteSWRLRule("RiskAssessment#1 Auto Potential Risk Assessment");
			 swrlRuleEngine.deleteSWRLRule("RiskAssessment#2 Auto Residual Risk Calculation for Bad Reputation Risk");
			 swrlRuleEngine.deleteSWRLRule("RiskAssessment#3 Auto Residual Risk for Deliberated Malicious SW Distribution");
			 swrlRuleEngine.deleteSWRLRule("RiskAssessment#4 Auto Residual Risk for Data Protection Compliance Risk");

		 }
		 
		 if(flag == 1) {
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#1 Auto Bad Reputation Threat in Classified Data");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#2 Auto Data Protection Threat");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#3 Auto Unintentional User Error Threat");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#4 Auto SW Vulnerabilities Threat");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#5 Auto Deliberated Malicious SW Distribution Threat");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#6 Auto Social Engineering Threat");
			 swrlRuleEngine.deleteSWRLRule("ThreatInventory#7 Auto Corporate Brand Image Damage Threat");
			 
			 swrlRuleEngine.deleteSWRLRule("RiskInventory#1 Auto Bad Reputation Risk");
			 swrlRuleEngine.deleteSWRLRule("RiskInventory#4 Wifi Anomaly + Threat");
			 swrlRuleEngine.deleteSWRLRule("RiskInventory#2 Auto Deliberated Malicious SW Distribution Risk");
			 swrlRuleEngine.deleteSWRLRule("RiskInventory#3 Auto Data Protection Risks Risk");
			 swrlRuleEngine.deleteSWRLRule("RiskInventory#5 Denial Of Service Risk");

		 }
		 
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		 
		 
	}
	
	//Load SWRL rules engine
	public void loadSWRLRiskAssessmentRules(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
	 
		 // Run the SWRL rules in the ontology
		// swrlRuleEngine.infer();
		float umbral = Configuration.umbral;
		//Assessment
		swrlRuleEngine.createSWRLRule("RiskAssessment#1 Auto Potential Risk Assessment", "cyberthreat_STIXDRM:isGeneratedBy(?r, ?th) ^ cyberthreat_DRM:threatens(?r, ?rs) ^ cibersituational-ontology:impact(?th, ?i) ^ cibersituational-ontology:probability(?th, ?p) ^ cyberthreat_DRM:Risk_Scope(?rs) ^ cyberthreat_DRM:Risk(?r) ^ cibersituational-ontology:type(?r, ?ty) ^ swrlb:add(?x, ?p, ?i) ^ cibersituational-ontology:namenazas(?r, ?n) ^ swrlx:makeOWLThing(?y, ?r, ?th) -> cyberthreat_DRM:PotentialRisk(?y) ^ cibersituational-ontology:probability(?y, ?p) ^ cibersituational-ontology:type(?y, ?ty) ^ cyberthreat_DRM:evaluates(?y, ?r) ^ cibersituational-ontology:impact(?y, ?i) ^ cyberthreat_DRM:threatens(?y, ?rs) ^ cibersituational-ontology:potentialRisk(?y, ?x) ^ cyberthreat_STIXDRM:isGeneratedBy(?y, ?th) ^ cibersituational-ontology:namenazas(?y, ?n)");
		swrlRuleEngine.createSWRLRule("RiskAssessment#2 Auto Residual Risk Calculation for Bad Reputation Risk", "cibersituational-ontology:type(?s, \"privilege-management-control\"^^rdfs:Literal) ^ cyberthreat_DRM:dependsOn(?rs, ?new_data) ^ cyberthreat_DRM:PotentialRisk(?x) ^ cibersituational-ontology:type(?x, \"Bad Reputation Risk\"^^rdf:PlainLiteral) ^ cyberthreat_DRM:threatens(?x, ?rs) ^ cyberthreat_DRM:Safeguards(?s) ^ cibersituational-ontology:drm_value(?s, ?v) ^ swrlb:subtract(?ar, ?prisk, ?v) ^ cibersituational-ontology:potentialRisk(?x, ?prisk) ^ cyberthreat_DRM:Data(?new_data) -> cibersituational-ontology:actualRisk(?x, ?ar) ^ cyberthreat_DRM:ResidualRisk(?x) ^ cyberthreat_DRM:isMitigatedBy(?x, ?s)");
		swrlRuleEngine.createSWRLRule("RiskAssessment#3 Auto Residual Risk for Deliberated Malicious SW Distribution", "cyberthreat_DRM:PotentialRisk(?x) ^ cibersituational-ontology:type(?x, \"Deliberated Malicious SW Distribution Risk\"^^rdf:PlainLiteral) ^ cibersituational-ontology:type(?s, \"control-against-malicious-sw\"^^rdfs:Literal) ^ cyberthreat_DRM:Safeguards(?s) ^ cibersituational-ontology:drm_value(?s, ?v) ^ swrlb:subtract(?ar, ?prisk, ?v) ^ cibersituational-ontology:potentialRisk(?x, ?prisk) -> cibersituational-ontology:actualRisk(?x, ?ar) ^ cyberthreat_DRM:ResidualRisk(?x) ^ cyberthreat_DRM:isMitigatedBy(?x, ?s)");
		swrlRuleEngine.createSWRLRule("RiskAssessment#4 Auto Residual Risk for Data Protection Compliance Risk", "cyberthreat_DRM:threatens(?x, ?rs) ^ cibersituational-ontology:type(?s, \"privacy-and-data-protection-control\") ^ cibersituational-ontology:drm_value(?s, ?v) ^ cibersituational-ontology:potentialRisk(?x, ?prisk) ^ cibersituational-ontology:type(?x, \"Data Protection Compliance Risk\"^^rdf:PlainLiteral) ^ swrlb:subtract(?ar, ?prisk, ?v) ^ cyberthreat_DRM:PotentialRisk(?x) ^ cyberthreat_DRM:Data(?new_data) ^ cyberthreat_DRM:dependsOn(?rs, ?new_data) ^ cyberthreat_DRM:PrivacyandDataProtectionControl(?s) -> cyberthreat_DRM:isMitigatedBy(?x, ?s) ^ cyberthreat_DRM:ResidualRisk(?x) ^ cibersituational-ontology:actualRisk(?x, ?ar)");

		
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		
		 
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
	

	@SuppressWarnings("resource")
	public static File copyFileOWL(File sourceFile, File destFile) throws IOException {
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
		return destFile;
	}
	
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
	
	
	public static boolean isEmptyAnomaliesFile(File filename ) throws IOException, ParseException{
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
	 	
	 	float intervalo = Configuration.intervalo;
	 	boolean done = false;
		Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
		 for(OWLNamedIndividual i:instances) {
			 System.out.println("Instance i "+i);
			 float n=0;
			 NodeSet<OWLNamedIndividual> wset = reasoner.getInstances(Anomaly.getWifi_sensor_anomaly(), true) ;
			 for(OWLNamedIndividual winstance : wset.getFlattened()) {
				 System.out.println("Instance winstance "+winstance);
				 OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":related-to", pm);
				 String mac1 = anomaly.obtainObjectPropertyValue(winstance, oproperty, o, reasoner);
				 String mac2 = anomaly.obtainObjectPropertyValue(i, oproperty, o, reasoner);
				 
				 if(mac1 != null && mac2 !=null && mac1.equals(mac2) && i!=winstance) {
					 n++;
					 System.out.println(n);
				 }				
			 }
			 if(n!=0) {
				 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, n, intervalo);
				 done=true;
				 n=0;
			 }
		 }
		 
		 for(OWLNamedIndividual i:instances) { 
			 float k=0;
			 NodeSet<OWLNamedIndividual> btset = reasoner.getInstances(Anomaly.getBt_sensor_anomaly(), true) ;
			 for(OWLNamedIndividual btinstance : btset.getFlattened()) {
				 
				 OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":related-to", pm);	
				 String mac1 = anomaly.obtainObjectPropertyValue(btinstance, oproperty, o, reasoner);
				 String mac2 = anomaly.obtainObjectPropertyValue(i, oproperty, o, reasoner);
				 if(mac1 != null && mac2 !=null && mac1.equals(mac2) && i!=btinstance) {
					 done = true;
					 k++;
				 }
				 
			 }
			 if(k!=0) {
				 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, k, intervalo);
				 done=true;
				 k=0;
			 }
		 	
		 } 
		 
		 for(OWLNamedIndividual i:instances) {
			 float j =0;
			 NodeSet<OWLNamedIndividual> rfset = reasoner.getInstances(Anomaly.getRf_sensor_anomaly(), true) ;
			 for(OWLNamedIndividual rfinstance : rfset.getFlattened()) {

				 System.out.println("Anomalia RF2 "+rfinstance);
				 OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_signal_frequency", pm);	
				 String mac1 = anomaly.obtainDataPropertyValue(rfinstance, dproperty, o, reasoner);
				 String mac2 = anomaly.obtainDataPropertyValue(i, dproperty, o, reasoner);
				 if(mac1 != null && mac2 !=null && mac1.equals(mac2) && i!= rfinstance) {
					 done = true;
					 j++;
				 }
			 }
			 if(j!=0) {
				 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, j, intervalo);
				 done=true;
				 j=0;
			 }
		 }
		 for(OWLNamedIndividual i:instances) {
			 float l =0;
			 NodeSet<OWLNamedIndividual> rmset = reasoner.getInstances(Anomaly.getRm_sensor_anomaly(), true) ;
			 for(OWLNamedIndividual rminstance : rmset.getFlattened()) {

				 System.out.println("Anomalia RF2 "+rminstance);
				 OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":has_IMEI", pm);	
				 String mac1 = anomaly.obtainDataPropertyValue(rminstance, dproperty, o, reasoner);
				 String mac2 = anomaly.obtainDataPropertyValue(i, dproperty, o, reasoner);
				 if(mac1 != null && mac2 !=null && mac1.equals(mac2) && i!= rminstance) {
					 done = true;
					 l++;
				 }
			 }
			 if(l!=0) {
				 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, l, intervalo);
				 done=true;
				 l=0;
			 }
		 }
		 
		 for(OWLNamedIndividual i:instances) {
			 float l =0;
			 NodeSet<OWLNamedIndividual> rmset = reasoner.getInstances(Anomaly.getIds_sensor_anomaly(), true) ;
			 for(OWLNamedIndividual rminstance : rmset.getFlattened()) {

				 System.out.println("Anomalia RF2 "+rminstance);
				 OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":dstip", pm);	
				 String mac1 = anomaly.obtainDataPropertyValue(rminstance, dproperty, o, reasoner);
				 String mac2 = anomaly.obtainDataPropertyValue(i, dproperty, o, reasoner);
				 if(mac1 != null && mac2 !=null && mac1.equals(mac2) && i!= rminstance) {
					 done = true;
					 l++;
				 }
			 }
			 if(l!=0) {
				 anomaly.modifiedSuspiciousValue(i, dataFactory, o, man, l, intervalo);
				 done=true;
				 l=0;
			 }
		 }
		
		man.saveOntology(o);
		return done;
	 }
	 
	 public static String obtainDataPropertyValue(OWLIndividual individual,OWLDataProperty dproperty, OWLOntology o, OWLReasoner reasoner) {
	        String result = null;
	   
	        Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
				for (OWLDataPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
				             result = ax.getObject().getLiteral().toString();
				         }
				}
	        return(result);
	    }
	 
	 public static String obtainObjectPropertyValue(OWLIndividual individual,OWLObjectProperty oproperty, OWLOntology o, OWLReasoner reasoner) {
	        String result = null;
	   
	        Set<OWLObjectPropertyAssertionAxiom> properties = o.getObjectPropertyAssertionAxioms(individual);
				for (OWLObjectPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(oproperty) && ax.getSubject().equals(individual)) {
				             result = ax.getObject().toString();
				         }
				}
	        return(result);
	    }
	 
 
	 public static Risks nRiskConfig(OWLDataFactory dataFactory, OWLOntology o, OWLOntologyManager man, OWLReasoner reasoner, String base) throws OWLOntologyStorageException {
			Risks risks = null;
			
			
		 	PrefixManager pm = new DefaultPrefixManager(base + "#");
			PrefixManager pmDRM = new DefaultPrefixManager(drm.base + "#");
			
			Set<OWLNamedIndividual> amenazasExistentes = new HashSet<OWLNamedIndividual>();
			OWLClass threatClass = dataFactory.getOWLClass(":Threat",pmDRM);
			System.out.println(threatClass);
				 
			Set<OWLNamedIndividual> setInstances = o.getIndividualsInSignature();
	        for (OWLNamedIndividual i : setInstances) {
	        	Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(i);
	        	for (OWLClassAssertionAxiom ax : classes) {
					if (ax.getClassExpression().equals(threatClass)) {
						System.out.println(i);
						amenazasExistentes.add(i);
						
				     }
				}
	         }
	        if(amenazasExistentes.size()>0) {
	        	risks = nAmenazasConfiguration(amenazasExistentes, o, man, dataFactory, base, reasoner);
	        	
	        }else {
	        	System.out.println("No existen amenazas");
	        	
	        }
	        
	        return risks;
	 }
	 
	 public static Risks nAmenazasConfiguration(Set<OWLNamedIndividual> amenazasExistentes, OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) throws OWLOntologyStorageException {
			Map<String, OWLNamedIndividual> riskinstances = new HashMap<String, OWLNamedIndividual>();
			
			PrefixManager pm = new DefaultPrefixManager(drm.base + "#");
			PrefixManager pmO = new DefaultPrefixManager(base + "#");
			
			numeroAmenazasPorRiesgo = new double[DRM.risk_names.length];
			for(int i=0; i< numeroAmenazasPorRiesgo.length-1; i++ ) {
				numeroAmenazasPorRiesgo[i] =0.0;
			}
			
			for(OWLNamedIndividual t: amenazasExistentes) {
				OWLDataProperty numType = dataFactory.getOWLDataProperty(":numType", pmO);
				String num = obtainDataPropertyValue(t, numType, o, reasoner);
				System.out.println(num);
				int numero=-1;
				if(StringUtils.isNumeric(num)) {
					numero = Integer.parseInt(num);
				}
				
				switch(numero) {
				case 1:
					numeroAmenazasPorRiesgo[1]++;
					
					break;
				case 4:
					numeroAmenazasPorRiesgo[4]++;
					break;
				case 5:
					numeroAmenazasPorRiesgo[5]++;
					break;
				case 11:
					numeroAmenazasPorRiesgo[11]++;
				
					break;
				case 14:
					numeroAmenazasPorRiesgo[14]++;
					break;
				case 15:
					numeroAmenazasPorRiesgo[15]++;
					System.out.println("DENIAL OF SERVICE");
					break;
				case 31:
					numeroAmenazasPorRiesgo[31]++;
					break;
				case 39:
					numeroAmenazasPorRiesgo[39]++;
					break;
				case 40:
					numeroAmenazasPorRiesgo[40]++;
					break;
				default:
					break;
	    		}	
				
			}
			Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
			for(OWLNamedIndividual k: instances) {
				System.out.println(k);
				int type;
				type = isRiskType(k, o, dataFactory, reasoner, drm.base);
				if(type!=-1) {	
					System.out.println("Entra para meter amenazas");
					OWLDataProperty property = dataFactory.getOWLDataProperty(":namenazas",pmO);
					createDataProperty(o, man, dataFactory, base, k, property, numeroAmenazasPorRiesgo[type]);
					System.out.println(numeroAmenazasPorRiesgo[type]);
					for(int i=0; i<instances.size();i++) {
						System.out.println("Metes el riesgo en riskinstances");
						OWLDataProperty typ = dataFactory.getOWLDataProperty(":type",pmO);
						String nameofrisk = obtainDataPropertyValue(k, typ, o, reasoner);
						System.out.println("INSTANCIA : "+k);
						riskinstances.put(nameofrisk, k);
					}
					
				}
				
			}
			Risks risks = new Risks(riskinstances, o, man, dataFactory,drm.base );
			man.saveOntology(o);
			return risks;
			
		}
	 
	 public static int isRiskType(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, OWLReasoner reasoner, String base_DRM) {
			PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
	        int result=-1;
	        for(int i = 0; i < DRM.risk_names.length; i++) {
	        	
	        	OWLClassExpression pr = dataFactory.getOWLClass(":"+DRM.risk_names[i], pmDRM);

	            Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
	    			for (OWLClassAssertionAxiom ax : classes) {
	    				if (ax.getClassExpression().equals(pr)) {
	    			             result = i;
	    			    }
	    			}  
	        }
			return result;
		}
	 
	 
	 
	
	public static void main(String[] args) throws OWLOntologyCreationException, IOException, ParseException, SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException, java.text.ParseException {
		OntologyApp onto_object =new OntologyApp();
		
		OWLOntology o = null;
		String base = null;
		
		//Ontology files are loaded, copy and original
		System.out.println("");
		System.out.println("Loading Ontology...");
		//File file = new File("./owl-files/cibersituational-ontov2.owl");
		File fileTmp = new File("./owl-files/cibersituational-ontov2-tmp.owl");
		//File fileTmp2 = new File("./owl-files/cibersituational-ontov2-tmp2.owl");
		//File copytmp2 = copyFileOWL(fileTmp, fileTmp2);

		
		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		o =  man.loadOntologyFromOntologyDocument(fileTmp);
		OWLDataFactory dataFactory = man.getOWLDataFactory();
		IRI documentIRI = o.getOntologyID().getOntologyIRI().get();
		base = documentIRI.toString();
		System.out.println("Ontology loaded\n");
	
		
		anomaly = new Anomaly(dataFactory, man, base);
		drm = new DRM(dataFactory, man, base);
		stix = new STIX(dataFactory, man, base);
		Configuration.runConfiguration();
		
		

		
		
		//Copy in other ontology
		//File fileAnom = copyFile(fileTmp);
		//OWLOntology o2 = null;
		//IRI iri = null;
		//OWLOntologyManager man2 = OWLManager.createOWLOntologyManager();
		//OWLDataFactory dataFactory2 = man2.getOWLDataFactory();
		//o2= man2.loadOntologyFromOntologyDocument(fileAnom);
		//iri = o2.getOntologyID().getOntologyIRI().get();
		//String base2 = iri.toString();
		
		
		while(true) {
			
			// CARGAR ACTIVOS
			
			//Load rules las de threat inventory y risk inventory
			System.out.println("Loading rules...\n");
			onto_object.deleteSWRLRules(o, man, dataFactory, base, 0);
			onto_object.loadSWRLRulesAnomaliesThreatsAndRisks(o, man, dataFactory, base);
			System.out.println("Rules Anomalies Threats And Risks loaded.\n");
			
			while(true) {
				//File to load information
				System.out.println("Loading data from BBDD into the ontology...\n");
				boolean updated = false;
				File ficheroJSONSensores = new File(pathAnomaliesFile);
				updated = onto_object.isEmptyAnomaliesFile(ficheroJSONSensores);
				if(updated) {
					//se crcea nueva ontologia copiando las anomalias y sustituye la o actual por otra
					loadedAnomalyInstances = onto_object.loadAnomaliesFromBBDD(o, man, ficheroJSONSensores, base, dataFactory);
					System.out.println("There have been loaded "+loadedAnomalyInstances+ " instances of new anomalies\n");

				}
				
				//Load STIX elements
				//File to load information
				System.out.println("Loading STIX data into the ontology...\n");
				boolean updatedSTIX = false;
				File ficheroJSONSTIX = new File(pathSTIXFile);
				updatedSTIX = onto_object.isEmptyAnomaliesFile(ficheroJSONSTIX);
				if(updatedSTIX) {
					//se crea nueva ontologia copiando las anomalias y sustituye la o actual por otra
					int loadedSTIXInstances=0;
					loadedSTIXInstances = onto_object.loadSTIXInstances(o, man, ficheroJSONSTIX, base, dataFactory);
					System.out.println("There have been loaded "+loadedSTIXInstances+ " instances of STIX\n");
				}
				
				if(updated || updatedSTIX){
					updated=false;
					updatedSTIX =false;
					break;
				}
				
				try {
					Thread.sleep(5000);
					
					//PONER QUE SI PASAN X SEGUNDOS Y NO HA LLEGADO NADA QUE VUELVA A RAZONAR O ALGO AUNQUE LO VEO UN POCO INUTIL PORQUE SINO HA CAMBIADO NADA PARA QUE LO VAS A HACER
				
				} catch (InterruptedException e) {
					e.printStackTrace();
				}			
				
			}
		//Razona sobre la nueva ontologia, ejecuto reglas 1 vez
		//Execute rules
		System.out.println("Infering from rules...\n");
		onto_object.inferSWRLEngine(o, man, dataFactory, base);
		System.out.println("Done.\n");
		
		//Cargar razonador
		System.out.println("Starting the reasoner...\n");
		OWLReasonerFactory reasonerFactory = PelletReasonerFactory.getInstance();
		PelletReasoner reasoner =  (PelletReasoner) reasonerFactory.createReasoner(o);
		reasoner.precomputeInferences();
		onto_object.loadReasoner(o, man, dataFactory, base, reasoner);
		
		if(loadedAnomalyInstances!=0) {
			System.out.println("Updated SUSPICIOUS VALUE "+onto_object.updateSuspiciousValue(dataFactory, o, man, reasoner, base));
		}
		loadedAnomalyInstances=0;

		Risks riskClassObject = nRiskConfig(dataFactory, o, man, reasoner, base);
		if(riskClassObject ==null) {
			break;
		}
		
		//borrar reglas de amenazas y riesgos inventory
		onto_object.deleteSWRLRules(o, man, dataFactory, base,1);
		onto_object.loadSWRLRiskAssessmentRules(o, man, dataFactory, base);
		//inferir para risk assessment
		onto_object.inferSWRLEngine(o, man, dataFactory, base);
		
		System.out.println("ACABAS DE INFERIR NUEVOS PR");
		
		RiskExtractor re = new RiskExtractor();
		//Datos actuales rtd
		RiskTotalData rtd = re.infoExtractor(man, o, base, dataFactory, riskClassObject);
		//re.jsonWriter(rtd);
		RiskCalculation rc = new RiskCalculation();
		//datos continuos del pasado
		Set<RiskTotalData> rtd_from_past = rc.extractDataFromJSON();
		RiskTotalData rtdfinal = rc.riskCalculation(rtd_from_past, rtd);
		re.jsonWriter(rtdfinal);
		
		
		//Calculo del riegso continuo
		
		

		
		//RiskCalculation r = new RiskCalculation();
		//Map<String, Float> dataRRisk = new HashMap<String, Float>();
		//dataRRisk = r.residualRiskCalculation(o, man, dataFactory, base, reasoner, drm.base);
		//Map<String, Float> dataPRisk = new HashMap<String, Float>();
		//dataPRisk = r.potentialRiskCalculation(o, man, dataFactory, base, reasoner, drm.base);
		
		//System.out.println("El riesgo residual discreto es: "+dataRRisk);
		//System.out.println("El riesgo potential discreto es: "+dataPRisk);
		
		//chart = new Chart(dataRRisk2,dataPRisk2 );
		//chart.barchartPaint("Residual Risk", "Potential Risk");
		
		
		}
		
		
		//System.out.println(onto_object.duplicatedThreats(dataFactory, o, man, reasoner, base));
		
		
		
		
		//Verificar si es necesario modificar el sv value porque haya anomalias referentes al mismo sitio
		//razonar
		//caluclar riesgo
		//Esperar mas anomalias
		
		//Cargar razonador
		//System.out.println("Starting the reasoner...\n");
		//onto_object.loadReasoner(o, man, dataFactory, base);
		
		

		
		
	}

}
