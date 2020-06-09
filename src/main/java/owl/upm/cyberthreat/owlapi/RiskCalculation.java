package owl.upm.cyberthreat.owlapi;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.apache.jena.riot.SysRIOT;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.thoughtworks.xstream.mapper.LocalConversionMapper;

public class RiskCalculation {

	/*EXTRAIGO INFO DEL FICHERO DATOS.JSON
	 * EXTRAIGO RIESGO POTENCIAL TOTAL, RIESGO RESIDUAL TOTAL, EL TIEMPO Y EL ARRAY 
	 * calculo riesgo potencial total en tX teniendo en cuenta tx-1, tx-2
	*/
	public static  final String fileDatosPath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/datos.json";

	
	public Set<RiskTotalData> extractDataFromJSON() throws IOException, ParseException {
		File filename = new File(fileDatosPath);
		Set<RiskTotalData> riskTotalDataArray = new HashSet<RiskTotalData>();
		//si eso copiarlo internamente por si derepente hay algo que lo este usando

		
		
		if(!filename.exists()) {
			System.out.println("There aren't past data");
			return riskTotalDataArray;
		}else {
		JSONParser jsonParser = new JSONParser();
		FileReader reader = new FileReader(filename);
		Object obj = jsonParser.parse(reader);
		System.out.println("Extrayendo los JSON objetos del fichero datos.json " + obj);
		JSONArray dataList = (JSONArray) obj;

        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject jObject = (JSONObject) dataList.get(i); 
        	String time = jObject.get("Time").toString();
        	float pTRisk = Float.parseFloat(jObject.get("Potential Total Risk").toString());
        	float rTRisk = Float.parseFloat(jObject.get("Residual Total Risk").toString());
        	double numThreatTotal = Double.parseDouble(jObject.get("Threat Total Number").toString());
        	JSONArray risksArray = (JSONArray) jObject.get("Risks");
        	Set<RiskData> riskDataSet = new HashSet<RiskData>();
        	for(int j = 0; j<risksArray.size() ;j++) {
        		
        		JSONObject risksObject = (JSONObject) risksArray.get(j); 
        		String riskName = risksObject.get("Risk Name").toString();
        		float pRisk = Float.parseFloat(risksObject.get("Potential Risk").toString());
        		float rRisk = Float.parseFloat(risksObject.get("Residual Risk").toString());
        		float threatNum = Float.parseFloat(risksObject.get("Threat Number").toString());
        		float impact = Float.parseFloat(risksObject.get("Impact Value").toString());
        		float probability = Float.parseFloat(risksObject.get("Probability Value").toString());
        		
        		if(!riskName.isEmpty()) {
        			
        			RiskData rd= new RiskData(riskName, threatNum, pRisk, rRisk, impact, probability);
        			riskDataSet.add(rd);
        		}
        		
        	}
        	
        	JSONArray risksMArray = (JSONArray) jObject.get("Strategies");
        	Set<RiskManagementData> riskMDataSet = new HashSet<RiskManagementData>();
        	for(int k = 0; k<risksArray.size() ;k++) {
        		
        		JSONObject risksMObject = (JSONObject) risksMArray.get(k); 
        		String riskName = risksMObject.get("Risk").toString();
        		float value = Float.parseFloat(risksMObject.get("Risk Value").toString());
        		String recommendation = risksMObject.get("Recommendation Strategy").toString();
        		

        		
        		if(!riskName.isEmpty()) {
        			
        			RiskManagementData rd= new RiskManagementData( value, recommendation, riskName);
        			riskMDataSet.add(rd);
        		}
        		
        	}
        	
        	
        	if(time!=null && riskDataSet.size()>0) {
        		RiskTotalData riskTD = new RiskTotalData(time, pTRisk, rTRisk, riskDataSet, numThreatTotal, riskMDataSet);
        		riskTotalDataArray.add(riskTD);
        	}
        	
        	System.out.println(riskTotalDataArray.size());
        }
        reader.close();        
        return riskTotalDataArray;
		}
	}
	
	
	public RiskTotalData riskCalculation(Set<RiskTotalData> riskTotalDataArray, RiskTotalData rtd) throws java.text.ParseException {
		//calculo riesgo continuo
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH);
		Date date = formatter.parse(rtd.getDate());	
		long rtdTime = date.getTime();
		
		if(riskTotalDataArray == null) {
			//devuelvo la medicion actual
			rtd.setpRiskTotalTimeFunction(rtd.getpRiskTotal());
			rtd.setrRiskTotalTimeFunction(rtd.getrRiskTotal());
			return rtd;
		}
		for (RiskTotalData ri : riskTotalDataArray) {
			Date datei = formatter.parse(ri.getDate());	
			long riTime = datei.getTime();
			double penTimeVariable = function(rtdTime, riTime);
			ri.setTimePenalizationl(penTimeVariable);
		}
		
		return calculateTimeFunctionRisk(rtd, riskTotalDataArray);
		
	}
	
	
	public RiskTotalData calculateTimeFunctionRisk(RiskTotalData rtd, Set<RiskTotalData> riskTotalDataArray) {
		
		rtd = riskCalculationPRTimeFunction(rtd, riskTotalDataArray);
		rtd = riskCalculationRRTimeFunction(rtd, riskTotalDataArray);
		return rtd;
	}
	public RiskTotalData riskCalculationPRTimeFunction(RiskTotalData rtd, Set<RiskTotalData> riskTotalDataArray) {
		double num = rtd.getNumThreatTotal() * rtd.getpRiskTotal()*1;
		double den =  rtd.getNumThreatTotal()*1;
		for(RiskTotalData rtdi : riskTotalDataArray){
			num += rtdi.getNumThreatTotal()*rtdi.getpRiskTotal()*rtdi.getTimePenalization();
			den += rtdi.getNumThreatTotal()*rtdi.getTimePenalization();
		}
		if(den == 0) {
			den = 1;
		}
		rtd.setpRiskTotalTimeFunction(num/den);
		return rtd;
	}
	public RiskTotalData riskCalculationRRTimeFunction(RiskTotalData rtd, Set<RiskTotalData> riskTotalDataArray) {
		double num = rtd.getNumThreatTotal() * rtd.getrRiskTotal()*1;
		double den =  rtd.getNumThreatTotal()*1;
		for(RiskTotalData rtdi : riskTotalDataArray){
			num += rtdi.getNumThreatTotal()*rtdi.getrRiskTotal()*rtdi.getTimePenalization();
			den += rtdi.getNumThreatTotal()*rtdi.getTimePenalization();
		}
		if(den == 0) {
			den = 1;
		}
		rtd.setrRiskTotalTimeFunction(num/den);
		return rtd;
	}
	
	//Funcion de penalizacion
	private double function(double rtdTime, double rtd_from_pastTime) {
		

		double ejex= Configuration.penalizationValue*60*1000;
		double limitNoPenalization = 0;
		double penalizationInterval = ejex;
		double timeFunction;
		
		double time = rtdTime-rtd_from_pastTime;

		//Si ha pasado poco tiempo no se castiga
		if(time <limitNoPenalization) {
			timeFunction=1;
		}
		//No se pone porque matematicamente la funcion da casi 0
		/*else if (tiempoTranscurrido>=limiteDeOlvido) {
			//si ha pasado mucho tiempo se olvidan las mediciones anteriores, ademas se garantiza que el resultado de la funcion no es negativo
			resultadoFuncionTiempo = 0;
		}*/
		else {
			timeFunction = Math.pow(Math.E, -(Math.pow(time,3)/(penalizationInterval*Math.pow(penalizationInterval/2,2))));
			
		}
		return timeFunction;
	}
	
	
	
}
