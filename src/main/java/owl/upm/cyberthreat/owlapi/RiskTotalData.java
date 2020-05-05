package owl.upm.cyberthreat.owlapi;

import java.util.Set;

public class RiskTotalData {

	private String date;
	private float pRiskTotal;
	private float rRiskTotal;
	private Set<RiskData> riskData;
	
	public RiskTotalData( String date, float pRiskTotal, float rRiskTotal, Set<RiskData> riskData) {
		this.date = date;
		this.pRiskTotal = pRiskTotal;
		this.rRiskTotal= rRiskTotal;
		this.riskData = riskData;
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

	public float getrRiskTotal() {
		return rRiskTotal;
	}

	public void setrRiskTotal(float rRiskTotal) {
		this.rRiskTotal = rRiskTotal;
	}

	public Set<RiskData>  getRiskData() {
		return riskData;
	}

	public void setRiskData(Set<RiskData>  riskData) {
		this.riskData = riskData;
	}
	
	
}
