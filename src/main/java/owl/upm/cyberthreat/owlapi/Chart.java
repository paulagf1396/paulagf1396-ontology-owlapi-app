package owl.upm.cyberthreat.owlapi;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.swing.BorderFactory;
import javax.swing.JFrame;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.block.BlockBorder;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.statistics.HistogramDataset;
import org.jfree.data.statistics.HistogramType;

import org.jfree.data.time.RegularTimePeriod;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;

public class Chart {
	 
	
	public static  final String fileDatosPath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/datos.json";	
	private static Set<RiskTotalData> riskTotalDataArray= new HashSet<RiskTotalData>();
	
	public Chart() {
		
		
	}
	
	public static Set<RiskTotalData> extractorReaderFromJSON() throws IOException, ParseException{
		File filename = new File(fileDatosPath);
		Set<RiskTotalData> riskTotalDataArray= new HashSet<RiskTotalData>();
		if(!filename.exists()) {
			System.out.println("There is no data");
		}
		else {
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
        	double pTRiskC = Float.parseFloat(jObject.get("Potential Total Risk Continuous").toString());
        	double rTRiskC = Float.parseFloat(jObject.get("Residual Total Risk Continuous").toString());
        	double numThreatTotal = Double.parseDouble(jObject.get("Threat Total Number").toString());
        	JSONArray risksArray = (JSONArray) jObject.get("Risks");
        	Set<RiskData> riskDataSet = new HashSet<RiskData>();
        	for(int j = 0; j<risksArray.size() ;j++) {
        		
        		JSONObject risksObject = (JSONObject) risksArray.get(j); 
        		String riskName = risksObject.get("Risk Name").toString();
        		float pRisk = Float.parseFloat(risksObject.get("Potential Risk").toString());
        		float rRisk = Float.parseFloat(risksObject.get("Residual Risk").toString());
        		float threatNum = Float.parseFloat(risksObject.get("Threat Number").toString());
        		
        		if(!riskName.isEmpty()) {
        			
        			RiskData rd= new RiskData(riskName, threatNum, pRisk, rRisk);
        			riskDataSet.add(rd);
        		}
        		
        	}
        	
        	
        	if(time!=null && riskDataSet.size()>0) {
        		RiskTotalData riskTD = new RiskTotalData(time, pTRisk, rTRisk, riskDataSet, numThreatTotal);
        		riskTD.setpRiskTotalTimeFunction(pTRiskC);
        		riskTD.setrRiskTotalTimeFunction(rTRiskC);
        		
        		riskTotalDataArray.add(riskTD);
        	}
        	
        	System.out.println(riskTotalDataArray.size());
        }
		}
        return riskTotalDataArray;

	}
	
	public static void barchartPaint() throws IOException, ParseException {
		riskTotalDataArray = extractorReaderFromJSON();
		String pr = "Potential Risk";
		String rr = "Residual Risk";
		DefaultCategoryDataset data = new DefaultCategoryDataset();
		for (RiskTotalData entry : riskTotalDataArray) {
			Set<RiskData> rds = new HashSet<RiskData>();
			rds = entry.getRiskData();
			for(RiskData rd : rds) {
				String name = rd.getRiskName();
				float prisk = rd.getpRisk();
				float rrisk = rd.getrRisk();
			
				data.setValue(prisk, pr, name);	
				data.setValue(rrisk, rr, name);	
			}
				
		}
		String plotTitle = "Historgram"; 
		String xaxis = "number";
		String yaxis = "value"; 
		JFreeChart barChart = ChartFactory.createBarChart(
                "Residual/Potential Risks",
                "Risks",
                "Risk Value",
                data,
                PlotOrientation.VERTICAL,
                true, true, false);
        ChartFrame frame = new ChartFrame("First", barChart);
		frame.pack();
		frame.setVisible(true);
		
	}
	
	public static void seriesGraph() throws IOException, ParseException {
		riskTotalDataArray = extractorReaderFromJSON();
		String pr = "Potential Risk Continuous";
		String rr = "Residual Risk Continuous";
		DefaultCategoryDataset data = new DefaultCategoryDataset( );
		for (RiskTotalData entry : riskTotalDataArray) {
			
			double prisk = entry.getpRiskTotalTimeFunction();
			System.out.println(prisk);
			double rrisk = entry.getrRiskTotalTimeFunction();
			String date = entry.getDate();
			data.addValue(prisk, pr, date);	
			data.addValue(rrisk, rr, date);			
		}

		JFreeChart lineChart = ChartFactory.createLineChart(
                "Evolución del riesgo",
                "Date",
                "Risk Value",
                data,
                PlotOrientation.VERTICAL,
                true, true, false);
        ChartFrame frame = new ChartFrame("First", lineChart);       
        
		frame.pack();
		frame.setVisible(true);
		
	}
	
	public static void seriesXYGraph() throws IOException, ParseException {
		riskTotalDataArray = extractorReaderFromJSON();
		String pr = "Potential Risk Continuous";
		String rr = "Residual Risk Continuous";
		TimeSeries series1 = new TimeSeries(pr);		
		for (RiskTotalData entry : riskTotalDataArray) {
			
			double prisk = entry.getpRiskTotalTimeFunction();
			double rrisk = entry.getrRiskTotalTimeFunction();
			String date = entry.getDate();
			SimpleDateFormat standardDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
			// (Define your formatter only once, then reuse)

			Date myDate = standardDateFormat.parse(date);
			// (you may want to catch a ParseException)
			
			
			series1.add( new Day(date), prisk);
					
		}

		JFreeChart lineChart = ChartFactory.createLineChart(
                "Evolución del riesgo",
                "Date",
                "Risk Value",
                data,
                PlotOrientation.VERTICAL,
                true, true, false);
        ChartFrame frame = new ChartFrame("First", lineChart);
        
        
        final XYPlot plot = lineChart.getXYPlot( );
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer( );
        renderer.setSeriesPaint( 0 , Color.RED );
        renderer.setSeriesPaint( 1 , Color.GREEN );
        renderer.setSeriesStroke( 0 , new BasicStroke( 4.0f ) );
        renderer.setSeriesStroke( 1 , new BasicStroke( 3.0f ) );
        plot.setRenderer( renderer ); 
        
        
        
        
		frame.pack();
		frame.setVisible(true);
		
	}
	

    public static void main(String[] args) {
    	try {
			seriesGraph();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Error "+e);
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error "+e);
		}
    }

}
