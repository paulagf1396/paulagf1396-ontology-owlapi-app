package owl.upm.cyberthreat.owlapi;

import java.util.Set;

public class RiskTotalData {

	private String date;
	private float pRiskTotal;
	private float rRiskTotal;
	private double pRiskTotalTimeFunction;
	private double rRiskTotalTimeFunction;
	private double numThreatTotal;
	private Set<RiskData> riskData;
	private Set<RiskManagementData> riskM;
	private transient double timePenalization;
	
	public RiskTotalData( String date, float pRiskTotal, float rRiskTotal, Set<RiskData> riskData, double numThreatTotal, Set<RiskManagementData> riskM) {
		this.date = date;
		this.pRiskTotal = pRiskTotal;
		this.rRiskTotal= rRiskTotal;
		this.riskData = riskData;
		this.riskM = riskM;
		this.numThreatTotal = numThreatTotal;
	}

	public String getDate() {
		return date;
	}

	public void setDate(String date) {
		this.date = date;
	}

	public float getpRiskTotal() {
		return pRiskTotal;
	}

	public void setpRiskTotal(float pRiskTotal) {
		this.pRiskTotal = pRiskTotal;
	}

	public double getpRiskTotalTimeFunction() {
		return pRiskTotalTimeFunction;
	}

	public void setpRiskTotalTimeFunction(double pRiskTotalTimeFunction) {
		this.pRiskTotalTimeFunction = pRiskTotalTimeFunction;
	}
	public float getrRiskTotal() {
		return rRiskTotal;
	}

	public void setrRiskTotal(float rRiskTotal) {
		this.rRiskTotal = rRiskTotal;
	}
	
	public double getrRiskTotalTimeFunction() {
		return rRiskTotalTimeFunction;
	}

	public void setrRiskTotalTimeFunction(double rRiskTotalTimeFunction) {
		this.rRiskTotalTimeFunction = rRiskTotalTimeFunction;
	}
	public double getNumThreatTotal() {
		return numThreatTotal;
	}

	public void setNumThreatTotal(double numThreatTotal) {
		this.numThreatTotal = numThreatTotal;
	}
	public double getTimePenalization() {
		return timePenalization;
	}

	public void setTimePenalizationl(double penalizationTime) {
		this.timePenalization = penalizationTime;
	}

	public Set<RiskData>  getRiskData() {
		return riskData;
	}

	public void setRiskData(Set<RiskData>  riskData) {
		this.riskData = riskData;
	}
	
	public Set<RiskManagementData>  getRiskM() {
		return riskM;
	}

	public void setRiskM(Set<RiskManagementData>  riskM) {
		this.riskM = riskM;
	}
	
	
}
