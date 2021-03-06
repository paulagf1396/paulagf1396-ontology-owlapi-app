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
import java.util.TimeZone;
import java.util.Map.Entry;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.text.DateFormatter;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnit;
import org.jfree.chart.axis.TickUnits;
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
import org.jfree.data.time.Day;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.Minute;
import org.jfree.data.time.RegularTimePeriod;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
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
        	for(int j = 0; j<risksArray.size() ;j++) {
        		
        		JSONObject risksMObject = (JSONObject) risksArray.get(j); 
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
	
	public static void seriesXYGraph() throws IOException, ParseException, java.text.ParseException {
		riskTotalDataArray = extractorReaderFromJSON();
		String pr = "Potential Risk Continuous";
		String rr = "Residual Risk Continuous";
		TimeSeriesCollection dataset = new TimeSeriesCollection();
		final TimeSeries series1 = new TimeSeries(pr);
		final TimeSeries series2 = new TimeSeries(rr);
		for (RiskTotalData entry : riskTotalDataArray) {
			
			double prisk = entry.getpRiskTotalTimeFunction();
			double rrisk = entry.getrRiskTotalTimeFunction();
			String date = entry.getDate();
			
		/*	String defaultTimezone = TimeZone.getDefault().getID();
			Date myDate = (new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ")).parse(date);

			System.out.println("string: " + date);
			System.out.println("defaultTimezone: " + defaultTimezone);
			System.out.println("date: " + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")).format(myDate.getTime()));
			
			*/

			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
			SimpleDateFormat output = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			Date d = sdf.parse(date);
			String formattedTime = output.format(d);
			
			
			series1.add( new Second(d), prisk);
			series2.add( new Second(d), rrisk);
					
		}
		dataset.addSeries(series1);
		dataset.addSeries(series2);
		JFreeChart chart = ChartFactory.createTimeSeriesChart(
                "Evolución del riesgo",
                "Date",
                "Risk Value",
                dataset,
                true, true, false);
		final XYPlot plot = chart.getXYPlot();
		plot.setBackgroundPaint(new Color(0xF7F7F7));
		plot.setDomainGridlinesVisible(true);
		plot.setDomainGridlinePaint(Color.LIGHT_GRAY);
        plot.setRangeGridlinePaint(Color.LIGHT_GRAY);
        ChartFrame frame = new ChartFrame("First", chart);
        
        
        
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer( );
        renderer.setSeriesPaint( 0 , new Color(0xE9A5FF) );
        renderer.setSeriesPaint( 1 , new Color(0xA5BCFF));
        renderer.setSeriesStroke( 0 , new BasicStroke( 2.0f ) );
        renderer.setSeriesStroke( 1 , new BasicStroke( 3.0f ) );
        plot.setRenderer( renderer ); 
        
        final DateAxis axis = (DateAxis) plot.getDomainAxis();
        axis.setDateFormatOverride(new SimpleDateFormat("hh:mm:ss a"));
        axis.setVerticalTickLabels(true);
		
        
        
		frame.pack();
		frame.setVisible(true);
		
	}
	

    public static void main(String[] args) throws java.text.ParseException {
    	try {
    		seriesXYGraph();
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
