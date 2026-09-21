"""
Forensic Audit Log Dashboard - Backend Engine.

Connects to the SQL Server database (PRDashboardDB) and serves
live forensic audit modules with zero mock/sample data.
"""

import logging
import os
import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import pyodbc
from dateutil import parser as dateparser
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
    force=True,
)
logger = logging.getLogger("forensic_audit")

load_dotenv(Path(__file__).with_name(".env"))

app = FastAPI(
    title="Apex Forensic Audit Suite",
    description="Live Cross-Ledger S/4HANA & Invoice Extraction Forensic Engine",
    version="2.6.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------------
# Database Connection & Safe Query Execution
# -------------------------------------------------------------------------

_FORBIDDEN_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|MERGE|EXEC|EXECUTE|GRANT|REVOKE|CREATE)\b",
    re.IGNORECASE,
)


class DatabaseConnectionError(Exception):
    pass


class DataSourceNotAvailable(Exception):
    def __init__(self, message: str, required_fields: List[str]):
        super().__init__(message)
        self.message = message
        self.required_fields = required_fields


def get_conn():
    server = (os.getenv("DB_SERVER") or "157.180.114.220").strip("'\" ")
    port = str(os.getenv("DB_PORT") or "1433").strip("'\" ")
    database = (os.getenv("DB_DATABASE") or os.getenv("DB_NAME") or "PRDashboardDB").strip("'\" ")
    user = (os.getenv("DB_USER") or "").strip("'\" ")
    password = (os.getenv("DB_PASSWORD") or os.getenv("DB_PASS") or "").strip("'\" ")
    driver = (os.getenv("DB_DRIVER") or "ODBC Driver 17 for SQL Server").strip("'\" ")

    if driver.endswith(".dylib") or driver.endswith(".so") or "/" in driver:
        driver_str = f"DRIVER={driver};"
    else:
        driver_str = f"DRIVER={{{driver}}};"

    conn_str = (
        f"{driver_str}"
        f"SERVER={server},{port};"
        f"DATABASE={database};"
        f"UID={user};"
        f"PWD={password};"
        "TrustServerCertificate=yes;"
    )

    try:
        return pyodbc.connect(conn_str, timeout=15)
    except Exception as err:
        try:
            import pymssql
            return pymssql.connect(
                server=server,
                port=int(port), # type: ignore
                database=database,
                user=user,
                password=password,
                login_timeout=15,
                as_dict=False,
            ) # type: ignore
        except Exception:
            logger.error("DB connection error: %s", err)
            raise DatabaseConnectionError("Unable to connect to the database.") from err


_SQL_LINE_COMMENT = re.compile(r"--[^\r\n]*")


def _strip_sql_comments(sql: str) -> str:
    """Drop `--` line comments. The audit SQL carries explanatory comments (same style as queries.md), and a
    comment containing a word like "drop", or a stray "%" / "?", would trip the read-only guard or the
    parameter binding, so comments never reach the guard or the driver."""
    return _SQL_LINE_COMMENT.sub("", sql)


def query(sql: str, params: Optional[list] = None) -> List[Dict[str, Any]]:
    """Run a read-only SELECT and return rows as a list of dicts."""
    sql = _strip_sql_comments(sql)
    if _FORBIDDEN_SQL.search(sql):
        raise ValueError("Blocked non-SELECT statement in forensic audit module")
    try:
        conn = get_conn()
    except Exception as e:
        logger.error("Database connection failed: %s", type(e).__name__)
        raise DatabaseConnectionError("Unable to connect to the database.") from e

    try:
        cur = conn.cursor()
        if conn.__class__.__module__.startswith("pymssql") and params:
            sql_exec = sql.replace("?", "%s")
            cur.execute(sql_exec, tuple(params))
        else:
            cur.execute(sql, params or [])

        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    finally:
        conn.close()


# -------------------------------------------------------------------------
# Shared Helpers
# -------------------------------------------------------------------------

def parse_date(s: Optional[Any]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return dateparser.parse(str(s), dayfirst=False, fuzzy=True)
    except Exception:
        return None


def to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(str(v).replace(",", "").replace("$", "").strip())
    except (TypeError, ValueError):
        return None


def clip(score: float) -> int:
    return int(max(0, min(100, round(score))))


def risk_level(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Elevated"
    if score >= 30:
        return "Medium"
    return "Low"


def norm(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s.lower() if s else None


def find_column(table: str, patterns: List[str]) -> Optional[str]:
    cols = query(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?",
        [table],
    )
    names = [c["COLUMN_NAME"] for c in cols]
    for pattern in patterns:
        rx = re.compile(pattern, re.IGNORECASE)
        for name in names:
            if rx.search(name):
                return name
    return None


def mask_value(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if len(s) <= 4:
        return "X" * len(s)
    return "X" * (len(s) - 4) + s[-4:]


def error_response(code: str, message: str, required_fields: Optional[List[str]] = None):
    body: Dict[str, Any] = {"success": False, "error": {"code": code, "message": message}}
    if required_fields is not None:
        body["error"]["required_fields"] = required_fields
    return JSONResponse(status_code=200, content=body)


# -------------------------------------------------------------------------
# Unified Pagination Base Model
# -------------------------------------------------------------------------

class BasePaginatedFilter(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=100, ge=1, description="Records per page (unlimited)")


# -------------------------------------------------------------------------
# AP Audit Request Models (All Paginated)
# -------------------------------------------------------------------------

class SplitTransactionsRequest(BasePaginatedFilter):
    approval_limit: float = 5000
    time_window_days: int = 3
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    supplier: Optional[str] = None
    created_by_user: Optional[str] = None


class SoDRequest(BasePaginatedFilter):
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    supplier: Optional[str] = None
    requester_id: Optional[str] = None
    approver_id: Optional[str] = None
    processor_id: Optional[str] = None
    status: Optional[str] = None


class MaverickRequest(BasePaginatedFilter):
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    supplier: Optional[str] = None
    min_amount: Optional[float] = None
    max_amount: Optional[float] = None


class LostDiscountRequest(BasePaginatedFilter):
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    supplier: Optional[str] = None
    min_discount_amount: Optional[float] = None


class EmployeeConflictRequest(BasePaginatedFilter):
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    vendor: Optional[str] = None
    employee_id: Optional[str] = None
    match_type: Optional[str] = None


# -------------------------------------------------------------------------
# Specific Forensic Scenarios Request Models (All Paginated)
# -------------------------------------------------------------------------

class ApprovalOverLimitFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    invoice_processed_by: Optional[str] = None
    po_created_by: Optional[str] = None
    tolerance_pct: Optional[float] = 0.0
    min_excess: Optional[float] = 0.0
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class POLessInvoiceFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    invoice_processed_by: Optional[str] = None
    min_amount: Optional[float] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class RetroactivePOFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    created_by_user: Optional[str] = None
    invoice_processed_by: Optional[str] = None
    min_days_late: Optional[int] = 1
    # FIVEBOT* preparers are back-loaded migration invoices (invoice dates in 2019-2020 against 2026 POs)
    exclude_bot_invoices: bool = True
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class ThreeWayDiscrepancyFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    min_amount_discrepancy: Optional[float] = 0.01
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class POUtilizationFilter(BasePaginatedFilter):
    po_number: Optional[str] = None
    supplier_name: Optional[str] = None
    po_created_by: Optional[str] = None
    utilization_status: Optional[str] = "ALL"
    min_utilization_pct: Optional[float] = None
    max_utilization_pct: Optional[float] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class TopSpendFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    min_spend_percentage: Optional[float] = None
    min_spend_amount: Optional[float] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class ExactDuplicatesFilter(BasePaginatedFilter):
    vendor_key: Optional[str] = None
    invoice_number: Optional[str] = None
    match_type: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class RoundPaymentsFilter(BasePaginatedFilter):
    vendor_key: Optional[str] = None
    # None = every tier of queries.md (multiples of 100 and up)
    round_multiple: Optional[int] = Field(default=None, ge=1)
    min_amount: Optional[float] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class FuzzyDuplicatesFilter(BasePaginatedFilter):
    vendor_key: Optional[str] = None
    clean_inv: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class POLineSameChargeFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class VendorInvoiceVariantsFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    clean_inv: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class POLineOverbilledFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    tolerance_pct: Optional[float] = 5.0
    min_excess: Optional[float] = 100.0
    repeated_only: bool = False
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class InvoiceNumberReuseFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    invoice_number: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class WeekendPaymentsFilter(BasePaginatedFilter):
    vendor_key: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class PODuplicateChargeFilter(BasePaginatedFilter):
    supplier_name: Optional[str] = None
    po_number: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


        


# -------------------------------------------------------------------------
# Module 1: Split Transactions
# -------------------------------------------------------------------------

def _compute_split_transactions(req: SplitTransactionsRequest) -> Dict[str, Any]:
    sql = """
        SELECT purchase_order_id AS purchase_order, CAST(created_by AS VARCHAR(50)) AS created_by_user, supplier_name AS supplier,
               TRY_CAST(REPLACE(REPLACE(price, ',', ''), '$', '') AS DECIMAL(18,2)) AS net_amount,
               TRY_CONVERT(datetime2, date_created) AS creation_dt,
               TRY_CONVERT(datetime2, order_date) AS po_date
        FROM [TicketSystemDBProd].[ticketsystem].[purchase_order_master]
        WHERE created_by IS NOT NULL
          AND supplier_name IS NOT NULL AND supplier_name <> ''
    """
    params: list = []
    if req.supplier:
        sql += " AND supplier_name = ?"
        params.append(req.supplier)
    if req.created_by_user:
        sql += " AND CAST(created_by AS VARCHAR(50)) = ?"
        params.append(req.created_by_user)

    rows = query(sql, params)

    po_map: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        po = r["purchase_order"]
        entry = po_map.setdefault(po, {
            "purchase_order": po,
            "created_by_user": r["created_by_user"],
            "supplier": r["supplier"],
            "amount": 0.0,
            "creation_dt": None,
            "po_date": None,
        })
        entry["amount"] += to_float(r["net_amount"]) or 0.0
        if r["creation_dt"] and (entry["creation_dt"] is None or r["creation_dt"] < entry["creation_dt"]):
            entry["creation_dt"] = r["creation_dt"]
        if r["po_date"] and (entry["po_date"] is None or r["po_date"] < entry["po_date"]):
            entry["po_date"] = r["po_date"]

    start = parse_date(req.start_date)
    end = parse_date(req.end_date)

    pos = []
    for entry in po_map.values():
        effective_date = entry["creation_dt"] or entry["po_date"]
        if effective_date is None:
            continue
        if start and effective_date < start:
            continue
        if end and effective_date > end:
            continue
        if entry["amount"] <= 0 or entry["amount"] >= req.approval_limit:
            continue
        entry["effective_date"] = effective_date
        pos.append(entry)

    grouped: Dict[tuple, list] = {}
    for p in pos:
        grouped.setdefault((p["created_by_user"], p["supplier"]), []).append(p)

    transactions = []
    for (user, supplier), group in grouped.items():
        group.sort(key=lambda x: x["effective_date"])
        i = 0
        n = len(group)
        while i < n:
            j = i
            while (j + 1 < n and
                   (group[j + 1]["effective_date"] - group[i]["effective_date"]).days <= req.time_window_days):
                j += 1
            cluster = group[i:j + 1]
            if len(cluster) >= 2:
                combined = sum(c["amount"] for c in cluster)
                if combined > req.approval_limit:
                    dates = [c["effective_date"] for c in cluster]
                    po_count = len(cluster)
                    ratio = combined / req.approval_limit if req.approval_limit else 1
                    same_day = (max(dates) - min(dates)).days == 0
                    score = 40 + min(20, (po_count - 2) * 8) + min(30, (ratio - 1) * 30) + (10 if same_day else 0)
                    score = clip(score)
                    transactions.append({
                        "risk_score": score,
                        "risk_level": risk_level(score),
                        "user": user,
                        "supplier": supplier,
                        "po_count": po_count,
                        "po_numbers": [c["purchase_order"] for c in cluster],
                        "po_breakdown": [
                            {"purchase_order": c["purchase_order"], "amount": round(c["amount"], 2),
                             "date": c["effective_date"].strftime("%Y-%m-%d")}
                            for c in cluster
                        ],
                        "combined_amount": round(combined, 2),
                        "approval_limit": req.approval_limit,
                        "amount_above_limit": round(combined - req.approval_limit, 2),
                        "date_range": f"{min(dates).strftime('%Y-%m-%d')} to {max(dates).strftime('%Y-%m-%d')}",
                        "reason": (
                            f"{po_count} purchase orders totaling {round(combined, 2)} created within "
                            f"{(max(dates) - min(dates)).days} day(s) by '{user}' with supplier '{supplier}', "
                            f"each individually below the {req.approval_limit} approval limit."
                        ),
                        "status": "Potential Split Transaction",
                    })
                i = j + 1
            else:
                i += 1

    transactions.sort(key=lambda t: t["risk_score"], reverse=True)

    summary = {
        "potential_split_transactions": len(transactions),
        "total_pos_involved": sum(t["po_count"] for t in transactions),
        "potential_split_value": round(sum(t["combined_amount"] for t in transactions), 2),
        "potential_approval_exposure": round(sum(t["amount_above_limit"] for t in transactions), 2),
        "high_risk_cases": sum(1 for t in transactions if t["risk_score"] >= 70),
    }

    offset = (req.page - 1) * req.page_size
    paginated_transactions = transactions[offset : offset + req.page_size]

    return {
        "success": True,
        "page": req.page,
        "page_size": req.page_size,
        "count": len(paginated_transactions),
        "total_count": len(transactions),
        "summary": summary,
        "transactions": paginated_transactions,
    }


@app.get("/api/audit/split-transactions")
def split_transactions(req: SplitTransactionsRequest = Query(default_factory=SplitTransactionsRequest)):
    try:
        return _compute_split_transactions(req)
    except DatabaseConnectionError as e:
        return error_response("DATABASE_CONNECTION_ERROR", str(e))
    except Exception:
        logger.exception("split-transactions failed")
        return error_response("DATABASE_CONNECTION_ERROR", "Unable to connect to the database.")


# -------------------------------------------------------------------------
# Module 2: SoD Violations
# -------------------------------------------------------------------------

# SQL is queries.md "SoD Violations". Filters are added on top, nothing else in the logic changes.
# DEVIATION D2: the PR link is PONumber = PR_mainData.EP_ID. queries.md joins ERP_PO_Number, which never
#   matches an invoice PONumber (0 of 165,000 POs), so Requester = Approver / Approver = Processor could not fire.
# Additive: invoice_date in the output so the date filter and the trend chart work.
_SOD_SQL = r"""
WITH inv AS (
	SELECT
		Invoice_ID,
		InvoiceNumber,
		Invoice_Name,
		Supplier_Name,
		PONumber,
		GrossAmount,
		Requester,
		Preparer,
		Payment_ID,
		Payment_StatusString,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date,
		LOWER(LTRIM(RTRIM(Requester))) AS requester_n,
		LOWER(LTRIM(RTRIM(Preparer)))  AS processor_n
	FROM [Invoice_Reconciliation_Flat]
	WHERE LineItem_Number = 1
		AND (? IS NULL OR Supplier_Name = ?)
		AND (? IS NULL OR Requester = ?)
		AND (? IS NULL OR Preparer = ?)
		AND (? IS NULL OR Payment_StatusString = ?)
		AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) >= ?)
		AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) <= ?)
),
pr AS (
	-- PR_mainData is one row per PR line, collapse it to one row per PR / PO
	SELECT
		PR_Number,
		NULLIF(LTRIM(RTRIM(EP_ID)), '') AS EP_ID,
		MAX(Requester)   AS PR_Requester,
		MAX(Approved_By) AS Approved_By
	FROM [PR_mainData]
	GROUP BY PR_Number, NULLIF(LTRIM(RTRIM(EP_ID)), '')
),
joined AS (
	SELECT
		inv.*,
		pr.PR_Number,
		pr.PR_Requester,
		pr.Approved_By,

		-- Requester = Approver (Approved_By is a '; ' separated list)
		CASE WHEN EXISTS (
			SELECT 1 FROM STRING_SPLIT(pr.Approved_By, ';') a
			WHERE LOWER(LTRIM(RTRIM(a.value))) IN (inv.requester_n, LOWER(LTRIM(RTRIM(pr.PR_Requester))))
		) THEN 1 ELSE 0 END AS Requester_Is_Approver,

		-- Approver = Processor (invoice Preparer is the processed-by person)
		CASE WHEN EXISTS (
			SELECT 1 FROM STRING_SPLIT(pr.Approved_By, ';') a
			WHERE LOWER(LTRIM(RTRIM(a.value))) = inv.processor_n
		) THEN 1 ELSE 0 END AS Approver_Is_Processor,

		-- Requester = Processor
		CASE WHEN inv.requester_n IS NOT NULL AND inv.requester_n = inv.processor_n
			THEN 1 ELSE 0 END AS Requester_Is_Processor
	FROM inv
	LEFT JOIN pr ON pr.EP_ID = inv.PONumber
)
SELECT
	Invoice_ID,
	InvoiceNumber,
	Invoice_Name,
	Supplier_Name,
	PONumber,
	PR_Number,
	GrossAmount,
	Requester,
	PR_Requester,
	Approved_By,
	Preparer,
	Payment_ID,
	Payment_StatusString,
	invoice_date,
	Requester_Is_Approver,
	Approver_Is_Processor,
	Requester_Is_Processor
FROM joined
WHERE (Requester_Is_Approver = 1
		OR Approver_Is_Processor = 1
		OR Requester_Is_Processor = 1)
	AND (? IS NULL OR Approved_By LIKE '%' + ? + '%')
ORDER BY GrossAmount DESC, Invoice_ID;
"""

# Invoices looked at (header rows) under the same filters, for the "transactions reviewed" figure.
_SOD_REVIEWED_SQL = """
SELECT COUNT(*) AS c
FROM [Invoice_Reconciliation_Flat]
WHERE LineItem_Number = 1
	AND (? IS NULL OR Supplier_Name = ?)
	AND (? IS NULL OR Requester = ?)
	AND (? IS NULL OR Preparer = ?)
	AND (? IS NULL OR Payment_StatusString = ?)
	AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) >= ?)
	AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) <= ?)
"""

_SOD_WEIGHTS = {"Requester = Approver": 40, "Approver = Processor": 30, "Requester = Processor": 10}


def _sod_date(s: Optional[str]) -> Optional[date]:
    d = parse_date(s)
    return d.date() if d else None


def _compute_sod(req: SoDRequest) -> Dict[str, Any]:
    start, end = _sod_date(req.start_date), _sod_date(req.end_date)
    filter_params: list = []
    for value in (req.supplier or None, req.requester_id or None, req.processor_id or None,
                  req.status or None, start, end):
        filter_params += [value, value]
    approver = req.approver_id or None

    rows = query(_SOD_SQL, filter_params + [approver, approver])
    reviewed = query(_SOD_REVIEWED_SQL, filter_params)[0]["c"]

    violations = []
    for r in rows:
        conflicts = []
        if r["Requester_Is_Approver"]:
            conflicts.append("Requester = Approver")
        if r["Requester_Is_Processor"]:
            conflicts.append("Requester = Processor")
        if r["Approver_Is_Processor"]:
            conflicts.append("Approver = Processor")

        amount = to_float(r["GrossAmount"]) or 0.0
        score = sum(_SOD_WEIGHTS[c] for c in conflicts)
        if amount >= 500000:
            score += 20
        elif amount >= 100000:
            score += 10
        elif amount >= 25000:
            score += 5
        score = clip(score)

        violations.append({
            "risk_score": score,
            "risk_level": risk_level(score),
            "case_id": r["Invoice_ID"],
            "invoice": (r["InvoiceNumber"] or "").strip() or r["Invoice_Name"],
            "po": (r["PONumber"] or "").strip() or None,
            "pr_number": r["PR_Number"],
            "supplier": r["Supplier_Name"],
            "requester": r["Requester"],
            "pr_requester": r["PR_Requester"],
            "approver": r["Approved_By"],
            "processor": r["Preparer"],
            "conflict": conflicts,
            "amount": round(amount, 2),
            "date": r["invoice_date"].strftime("%Y-%m-%d") if r["invoice_date"] else None,
            "payment_id": r["Payment_ID"],
            "payment_status": r["Payment_StatusString"],
        })

    violations.sort(key=lambda v: (v["risk_score"], v["amount"]), reverse=True)

    summary = {
        "potential_sod_violations": len(violations),
        "transactions_reviewed": reviewed,
        "affected_invoices": len({v["case_id"] for v in violations}),
        "affected_suppliers": len({v["supplier"] for v in violations if v["supplier"]}),
        "high_risk_cases": sum(1 for v in violations if v["risk_score"] >= 70),
    }

    offset = (req.page - 1) * req.page_size
    paginated_violations = violations[offset : offset + req.page_size]

    return {
        "success": True,
        "page": req.page,
        "page_size": req.page_size,
        "count": len(paginated_violations),
        "total_count": len(violations),
        "summary": summary,
        "violations": paginated_violations,
        "data_notes": [
            "Invoice level (queries.md SoD): requester = invoice Requester / PR Requester, approver = PR_mainData.Approved_By "
            "(PR joined on PONumber = EP_ID), processor = invoice Preparer.",
            "Requester / Preparer hold the Ariba UniqueName while Approved_By holds display names, so Requester = Approver "
            "only fires where the two forms are equal (an undercount). Requester = Processor is most of the rows and is scored low.",
            "Invoices without a PO, or whose PO has no PR, have no approver and can only show Requester = Processor.",
        ],
    }


@app.get("/api/audit/sod-violations")
def sod_violations(req: SoDRequest = Query(default_factory=SoDRequest)):
    try:
        return _compute_sod(req)
    except DatabaseConnectionError as e:
        return error_response("DATABASE_CONNECTION_ERROR", str(e))
    except Exception:
        logger.exception("sod-violations failed")
        return error_response("DATABASE_CONNECTION_ERROR", "Unable to connect to the database.")


# -------------------------------------------------------------------------
# Module 3: Maverick Spend
# -------------------------------------------------------------------------

def _compute_maverick(req: MaverickRequest) -> Dict[str, Any]:
    sql = """
        SELECT dedup_key,
               MAX(id) AS id,
               MAX(InvoiceNumber) AS InvoiceNumber,
               MAX(SupplierName) AS SupplierName,
               MAX(NULLIF(PONumber, '')) AS PONumber,
               MAX(InvoiceDate) AS InvoiceDate,
               MAX(TRY_CAST(REPLACE(REPLACE(Total, ',', ''), '$', '') AS DECIMAL(18,2))) AS Total,
               MIN(created_at) AS created_at
        FROM (
            SELECT inv.*, COALESCE(NULLIF(inv.InvoiceNumber, ''), CONCAT('PDFID:', inv.pdf_id)) AS dedup_key
            FROM dbo.Invoice_extracted_data inv
            INNER JOIN dbo.FileInput fi ON fi.pdf_id = inv.pdf_id
        ) x
        WHERE 1=1
    """
    params: list = []
    if req.supplier:
        sql += " AND SupplierName = ?"
        params.append(req.supplier)
    if req.start_date:
        d = parse_date(req.start_date)
        if d:
            sql += " AND created_at >= ?"
            params.append(d)
    if req.end_date:
        d = parse_date(req.end_date)
        if d:
            sql += " AND created_at <= ?"
            params.append(d)
    sql += " GROUP BY dedup_key"

    rows = query(sql, params)

    valid_pos = {
        r["purchase_order"]
        for r in query(
            "SELECT DISTINCT purchase_order_id AS purchase_order FROM [TicketSystemDBProd].[ticketsystem].[purchase_order_master] "
            "WHERE purchase_order_id IS NOT NULL"
        )
    }

    transactions = []
    for r in rows:
        po_number = (r["PONumber"] or "").strip()
        amount = to_float(r["Total"])

        if req.min_amount is not None and (amount is None or amount < req.min_amount):
            continue
        if req.max_amount is not None and (amount is None or amount > req.max_amount):
            continue

        if not po_number:
            reason = "Invoice has no PO number on record"
            base_score = 60
        elif po_number not in valid_pos:
            reason = "PO number on the invoice does not exist in the purchase order table"
            base_score = 50
        else:
            continue

        score = base_score
        if amount:
            if amount >= 100000:
                score += 20
            elif amount >= 25000:
                score += 10
            elif amount >= 5000:
                score += 5
        score = clip(score)

        transactions.append({
            "risk_score": score,
            "risk_level": risk_level(score),
            "case_id": f"INV-{r['id']}",
            "invoice": r["InvoiceNumber"],
            "supplier": r["SupplierName"],
            "po_number": po_number or None,
            "amount": round(amount, 2) if amount is not None else None,
            "invoice_date": r["InvoiceDate"],
            "reason": reason,
            "status": "Potential Maverick Spend",
        })

    transactions.sort(key=lambda t: t["risk_score"], reverse=True)

    summary = {
        "potential_maverick_transactions": len(transactions),
        "affected_invoices": len(transactions),
        "affected_suppliers": len({t["supplier"] for t in transactions if t["supplier"]}),
        "potential_maverick_value": round(sum(t["amount"] for t in transactions if t["amount"]), 2),
        "high_risk_cases": sum(1 for t in transactions if t["risk_score"] >= 70),
    }

    offset = (req.page - 1) * req.page_size
    paginated_transactions = transactions[offset : offset + req.page_size]

    return {
        "success": True,
        "page": req.page,
        "page_size": req.page_size,
        "count": len(paginated_transactions),
        "total_count": len(transactions),
        "summary": summary,
        "transactions": paginated_transactions,
    }


@app.get("/api/audit/maverick-spend")
def maverick_spend(req: MaverickRequest = Query(default_factory=MaverickRequest)):
    try:
        return _compute_maverick(req)
    except DatabaseConnectionError as e:
        return error_response("DATABASE_CONNECTION_ERROR", str(e))
    except Exception:
        logger.exception("maverick-spend failed")
        return error_response("DATABASE_CONNECTION_ERROR", "Unable to connect to the database.")


# -------------------------------------------------------------------------
# Module 4: Lost Discounts
# -------------------------------------------------------------------------

_PAID_DATE_PATTERN = re.compile(
    r"(actual.*pay|paid_date|payment.*actual|clear(ed|ing)?.*date|remit.*date)",
    re.IGNORECASE,
)


def _lost_discount_data_available() -> Optional[List[str]]:
    missing = []
    all_cols = query(
        "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_NAME IN ('S4_Invoice_Data','S4_Supplier_Invoice_Data',"
        "'Invoice_Reconciliation_Flat','Invoice_extracted_data')"
    )
    has_paid_date = any(_PAID_DATE_PATTERN.search(c["COLUMN_NAME"]) for c in all_cols)
    if not has_paid_date:
        missing.append(
            "an actual payment / cleared date field (database currently only has scheduled/planned "
            "dates and workflow statuses, not confirmed payment execution dates)"
        )

    nonzero_discount_rows = query(
        "SELECT COUNT(*) AS c FROM dbo.S4_Invoice_Data "
        "WHERE cash_discount1_percent > 0 OR cash_discount2_percent > 0"
    )[0]["c"]
    nonzero_discount_rows += query(
        "SELECT COUNT(*) AS c FROM dbo.S4_Supplier_Invoice_Data "
        "WHERE TRY_CAST(cash_discount1_percent AS DECIMAL(18,4)) > 0 "
        "OR TRY_CAST(cash_discount2_percent AS DECIMAL(18,4)) > 0"
    )[0]["c"]
    if nonzero_discount_rows == 0:
        missing.append(
            "populated early-payment discount terms (columns exist on S4_Invoice_Data / "
            "S4_Supplier_Invoice_Data but every row currently evaluates to 0)"
        )

    return missing or None


def _compute_lost_discounts(req: LostDiscountRequest) -> Dict[str, Any]:
    missing = _lost_discount_data_available()
    if missing:
        raise DataSourceNotAvailable(
            "Payment and/or discount data is not available in the database.",
            missing,
        )

    paid_date_col = None
    for c in query(
        "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='S4_Invoice_Data'"
    ):
        if _PAID_DATE_PATTERN.search(c["COLUMN_NAME"]):
            paid_date_col = c["COLUMN_NAME"]
            break

    sql = f"""
        SELECT supplier_invoice, invoicing_party, invoice_gross_amount,
               posting_date, due_calculation_base_date, cash_discount1_percent,
               cash_discount1_days, cash_discount2_percent, cash_discount2_days,
               payment_terms, [{paid_date_col}] AS paid_date
        FROM dbo.S4_Invoice_Data
        WHERE (cash_discount1_percent > 0 OR cash_discount2_percent > 0)
          AND [{paid_date_col}] IS NOT NULL
    """
    params: list = []
    if req.supplier:
        sql += " AND invoicing_party = ?"
        params.append(req.supplier)
    if req.start_date:
        d = parse_date(req.start_date)
        if d:
            sql += " AND posting_date >= ?"
            params.append(d)
    if req.end_date:
        d = parse_date(req.end_date)
        if d:
            sql += " AND posting_date <= ?"
            params.append(d)

    rows = query(sql, params)

    transactions = []
    for r in rows:
        base_date = parse_date(r["due_calculation_base_date"] or r["posting_date"])
        discount_days = r["cash_discount1_days"] or r["cash_discount2_days"]
        discount_pct = to_float(r["cash_discount1_percent"]) or to_float(r["cash_discount2_percent"]) or 0.0
        amount = to_float(r["invoice_gross_amount"]) or 0.0
        paid_date = parse_date(r["paid_date"])

        if not (base_date and discount_days is not None and paid_date):
            continue

        deadline = base_date + timedelta(days=discount_days)
        if paid_date <= deadline:
            continue

        potential_discount = round(amount * discount_pct / 100.0, 2)
        if req.min_discount_amount is not None and potential_discount < req.min_discount_amount:
            continue

        days_late = (paid_date - deadline).days
        score = clip(30 + min(40, days_late) + (20 if amount >= 100000 else 10 if amount >= 25000 else 0))

        transactions.append({
            "risk_score": score,
            "risk_level": risk_level(score),
            "case_id": r["supplier_invoice"],
            "invoice": r["supplier_invoice"],
            "supplier": r["invoicing_party"],
            "invoice_amount": round(amount, 2),
            "discount_percent": discount_pct,
            "discount_amount": potential_discount,
            "discount_deadline": deadline.strftime("%Y-%m-%d"),
            "payment_date": paid_date.strftime("%Y-%m-%d"),
            "days_late": days_late,
            "potential_lost_discount": potential_discount,
            "status": "Potential Lost Discount",
        })

    transactions.sort(key=lambda t: t["risk_score"], reverse=True)
    summary = {
        "potential_lost_discount_cases": len(transactions),
        "affected_invoices": len(transactions),
        "affected_suppliers": len({t["supplier"] for t in transactions if t["supplier"]}),
        "potential_lost_discount_value": round(sum(t["potential_lost_discount"] for t in transactions), 2),
        "high_risk_cases": sum(1 for t in transactions if t["risk_score"] >= 70),
    }

    offset = (req.page - 1) * req.page_size
    paginated_transactions = transactions[offset : offset + req.page_size]

    return {
        "success": True,
        "page": req.page,
        "page_size": req.page_size,
        "count": len(paginated_transactions),
        "total_count": len(transactions),
        "summary": summary,
        "transactions": paginated_transactions,
    }


@app.get("/api/audit/lost-discounts")
def lost_discounts(req: LostDiscountRequest = Query(default_factory=LostDiscountRequest)):
    try:
        return _compute_lost_discounts(req)
    except DataSourceNotAvailable as e:
        return error_response("DATA_SOURCE_NOT_AVAILABLE", e.message, e.required_fields)
    except DatabaseConnectionError as e:
        return error_response("DATABASE_CONNECTION_ERROR", str(e))
    except Exception:
        logger.exception("lost-discounts failed")
        return error_response("DATABASE_CONNECTION_ERROR", "Unable to connect to the database.")


# -------------------------------------------------------------------------
# Module 5: Employee Conflicts
# -------------------------------------------------------------------------

_EMPLOYEE_TABLE = "ConsolidatedGroupExport"
_VENDOR_TABLE = "Suppliers_master"

_TAX_PATTERNS = [r"tax.?number", r"tax.?id", r"^tax$"]
_BANK_PATTERNS = [r"bank.?account", r"^bank_?info$"]
_ADDRESS_PATTERNS = [r"(?<!email)address"]


def _resolve_employee_conflict_columns():
    return {
        "employee_id": find_column(_EMPLOYEE_TABLE, [r"^uniquename$"]) or "UniqueName",
        "employee_name": find_column(_EMPLOYEE_TABLE, [r"^name$"]) or "Name",
        "employee_tax": find_column(_EMPLOYEE_TABLE, _TAX_PATTERNS),
        "employee_bank": find_column(_EMPLOYEE_TABLE, _BANK_PATTERNS),
        "employee_address": find_column(_EMPLOYEE_TABLE, _ADDRESS_PATTERNS),
        "employee_link": find_column(_EMPLOYEE_TABLE, [r"SAPEmployeeSupplierID"]),
        "vendor_id": find_column(_VENDOR_TABLE, [r"^supplier_code$"]) or "supplier_code",
        "vendor_name": find_column(_VENDOR_TABLE, [r"^supplier_name$"]) or "supplier_name",
        "vendor_tax": find_column(_VENDOR_TABLE, _TAX_PATTERNS),
        "vendor_bank": find_column(_VENDOR_TABLE, _BANK_PATTERNS),
        "vendor_address": find_column(_VENDOR_TABLE, _ADDRESS_PATTERNS),
        "vendor_created": find_column(_VENDOR_TABLE, [r"^created_at$"]),
    }


def _employee_conflict_availability(cols: Dict[str, Optional[str]]) -> Optional[List[str]]:
    missing = []
    if not cols["employee_tax"]:
        missing.append(f"employee_tax_id (no tax-ID column exists on dbo.{_EMPLOYEE_TABLE})")
    if not cols["employee_bank"]:
        missing.append(f"employee_bank_account (no bank-account column exists on dbo.{_EMPLOYEE_TABLE})")
    if not cols["employee_address"]:
        missing.append(f"employee_address (no address column exists on dbo.{_EMPLOYEE_TABLE})")

    link_populated = False
    if cols["employee_link"]:
        row = query(
            f"SELECT COUNT(*) AS c FROM dbo.[{_EMPLOYEE_TABLE}] "
            f"WHERE [{cols['employee_link']}] IS NOT NULL AND [{cols['employee_link']}] <> ''"
        )[0]
        link_populated = row["c"] > 0
        if not link_populated:
            missing.append(
                f"a populated {cols['employee_link']} linking employees to vendors (column exists but is empty)"
            )
    else:
        missing.append(f"a direct employee-to-vendor link column on dbo.{_EMPLOYEE_TABLE}")

    if not cols["vendor_tax"]:
        missing.append(f"vendor_tax_id (no tax-ID column exists on dbo.{_VENDOR_TABLE})")
    if not cols["vendor_bank"]:
        missing.append(f"vendor_bank_account (no bank-account column exists on dbo.{_VENDOR_TABLE})")
    if not cols["vendor_address"]:
        missing.append(f"vendor_address (no address column exists on dbo.{_VENDOR_TABLE})")

    usable = (
        (cols["employee_tax"] and cols["vendor_tax"]) or
        (cols["employee_bank"] and cols["vendor_bank"]) or
        (cols["employee_address"] and cols["vendor_address"]) or
        link_populated
    )
    return None if usable else missing


_MATCH_WEIGHTS = {"Tax ID": 50, "Bank Account": 35, "Address": 15, "SAP Employee-Supplier Link": 50}


def _match_key(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s.upper() if s else None


def _address_key(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = re.sub(r"\s+", " ", str(v).strip())
    return s.upper() if s else None


def _compute_employee_conflicts(req: EmployeeConflictRequest) -> Dict[str, Any]:
    cols = _resolve_employee_conflict_columns()
    missing = _employee_conflict_availability(cols)
    if missing:
        raise DataSourceNotAvailable(
            "Vendor Master and/or HR Employee Master data is not available in the "
            "database in a form that supports employee-vendor matching.",
            missing,
        )

    emp_select = [f"[{cols['employee_id']}] AS employee_id", f"[{cols['employee_name']}] AS employee_name"]
    if cols["employee_tax"]:
        emp_select.append(f"[{cols['employee_tax']}] AS employee_tax")
    if cols["employee_bank"]:
        emp_select.append(f"[{cols['employee_bank']}] AS employee_bank")
    if cols["employee_address"]:
        emp_select.append(f"[{cols['employee_address']}] AS employee_address")
    if cols["employee_link"]:
        emp_select.append(f"[{cols['employee_link']}] AS employee_link")
    employees = query(f"SELECT DISTINCT {', '.join(emp_select)} FROM dbo.[{_EMPLOYEE_TABLE}]")

    vendor_select = [f"[{cols['vendor_id']}] AS vendor_id", f"[{cols['vendor_name']}] AS vendor_name"]
    if cols["vendor_tax"]:
        vendor_select.append(f"[{cols['vendor_tax']}] AS vendor_tax")
    if cols["vendor_bank"]:
        vendor_select.append(f"[{cols['vendor_bank']}] AS vendor_bank")
    if cols["vendor_address"]:
        vendor_select.append(f"[{cols['vendor_address']}] AS vendor_address")
    if cols["vendor_created"]:
        vendor_select.append(f"[{cols['vendor_created']}] AS vendor_created")

    vendor_sql = f"SELECT DISTINCT {', '.join(vendor_select)} FROM dbo.[{_VENDOR_TABLE}] WHERE 1=1"
    vendor_params: list = []
    if req.vendor:
        vendor_sql += f" AND ([{cols['vendor_id']}] = ? OR [{cols['vendor_name']}] = ?)"
        vendor_params += [req.vendor, req.vendor]
    vendors = query(vendor_sql, vendor_params)

    by_tax: Dict[str, list] = {}
    by_bank: Dict[str, list] = {}
    by_address: Dict[str, list] = {}
    by_link: Dict[str, list] = {}
    for e in employees:
        if cols["employee_tax"]:
            k = _match_key(e.get("employee_tax"))
            if k:
                by_tax.setdefault(k, []).append(e)
        if cols["employee_bank"]:
            k = _match_key(e.get("employee_bank"))
            if k:
                by_bank.setdefault(k, []).append(e)
        if cols["employee_address"]:
            k = _address_key(e.get("employee_address"))
            if k:
                by_address.setdefault(k, []).append(e)
        if cols["employee_link"]:
            k = _match_key(e.get("employee_link"))
            if k:
                by_link.setdefault(k, []).append(e)

    start = parse_date(req.start_date)
    end = parse_date(req.end_date)
    match_type_filter = norm(req.match_type).replace(" ", "_").replace("-", "_") if req.match_type else None

    pairs: Dict[tuple, Dict[str, Any]] = {}
    for v in vendors:
        if cols["vendor_created"] and v.get("vendor_created"):
            vc = parse_date(v["vendor_created"])
            if start and vc and vc < start:
                continue
            if end and vc and vc > end:
                continue

        candidates: Dict[str, set] = {}
        if cols["vendor_tax"]:
            k = _match_key(v.get("vendor_tax"))
            if k and k in by_tax:
                for e in by_tax[k]:
                    candidates.setdefault(e["employee_id"], set()).add("Tax ID")
        if cols["vendor_bank"]:
            k = _match_key(v.get("vendor_bank"))
            if k and k in by_bank:
                for e in by_bank[k]:
                    candidates.setdefault(e["employee_id"], set()).add("Bank Account")
        if cols["vendor_address"]:
            k = _address_key(v.get("vendor_address"))
            if k and k in by_address:
                for e in by_address[k]:
                    candidates.setdefault(e["employee_id"], set()).add("Address")
        k = _match_key(v.get("vendor_id"))
        if k and k in by_link:
            for e in by_link[k]:
                candidates.setdefault(e["employee_id"], set()).add("SAP Employee-Supplier Link")

        if not candidates:
            continue

        emp_by_id = {e["employee_id"]: e for e in employees}
        for emp_id, match_types in candidates.items():
            if req.employee_id and emp_id != req.employee_id:
                continue
            key = (emp_id, v["vendor_id"])
            if key in pairs:
                pairs[key]["match_type"] = sorted(
                    set(pairs[key]["match_type"]) | match_types,
                    key=lambda m: -_MATCH_WEIGHTS[m],
                )
            else:
                e = emp_by_id[emp_id]
                pairs[key] = {
                    "employee": e,
                    "vendor": v,
                    "match_type": sorted(match_types, key=lambda m: -_MATCH_WEIGHTS[m]),
                }

    conflicts = []
    for i, ((emp_id, vendor_id), pair) in enumerate(
        sorted(pairs.items(), key=lambda kv: sum(_MATCH_WEIGHTS[m] for m in kv[1]["match_type"]), reverse=True),
        start=1,
    ):
        match_types = pair["match_type"]
        if match_type_filter and match_type_filter not in [
            m.lower().replace(" ", "_").replace("-", "_") for m in match_types
        ]:
            continue

        e, v = pair["employee"], pair["vendor"]
        score = clip(sum(_MATCH_WEIGHTS[m] for m in match_types))

        match_details = {}
        if cols["employee_tax"] and cols["vendor_tax"]:
            match_details["tax_id"] = {
                "result": "MATCH" if "Tax ID" in match_types else "NO MATCH",
                "employee_value_masked": mask_value(e.get("employee_tax")),
                "vendor_value_masked": mask_value(v.get("vendor_tax")),
            }
        if cols["employee_bank"] and cols["vendor_bank"]:
            match_details["bank_account"] = {
                "result": "MATCH" if "Bank Account" in match_types else "NO MATCH",
                "employee_value_masked": mask_value(e.get("employee_bank")),
                "vendor_value_masked": mask_value(v.get("vendor_bank")),
            }
        if cols["employee_address"] and cols["vendor_address"]:
            match_details["address"] = {
                "result": "MATCH" if "Address" in match_types else "NO MATCH",
                "employee_value": e.get("employee_address") if "Address" in match_types else None,
                "vendor_value": v.get("vendor_address") if "Address" in match_types else None,
            }
        if "SAP Employee-Supplier Link" in match_types:
            match_details["sap_link"] = {"result": "MATCH"}

        reason = (
            f"Employee and vendor records share matching {', '.join(m.lower() for m in match_types)} information."
        )

        conflicts.append({
            "case_id": f"EMP{i:03d}",
            "employee_id": e["employee_id"],
            "employee_name": e["employee_name"],
            "vendor_id": v["vendor_id"],
            "vendor_name": v["vendor_name"],
            "match_type": match_types,
            "match_count": len(match_types),
            "match_details": match_details,
            "risk_score": score,
            "risk_level": risk_level(score),
            "reason": reason,
            "status": "New",
        })

    conflicts.sort(key=lambda c: c["risk_score"], reverse=True)

    summary = {
        "potential_employee_conflicts": len(conflicts),
        "affected_employees": len({c["employee_id"] for c in conflicts}),
        "affected_vendors": len({c["vendor_id"] for c in conflicts}),
        "high_risk_cases": sum(1 for c in conflicts if c["risk_score"] >= 70),
    }

    offset = (req.page - 1) * req.page_size
    paginated_conflicts = conflicts[offset : offset + req.page_size]

    filters_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    return {
        "success": True,
        "page": req.page,
        "page_size": req.page_size,
        "count": len(paginated_conflicts),
        "total_count": len(conflicts),
        "filters": filters_dict,
        "summary": summary,
        "conflicts": paginated_conflicts,
    }


@app.get("/api/audit/employee-conflicts")
def employee_conflicts(req: EmployeeConflictRequest = Query(default_factory=EmployeeConflictRequest)):
    try:
        return _compute_employee_conflicts(req)
    except DataSourceNotAvailable as e:
        return error_response("DATA_SOURCE_NOT_AVAILABLE", e.message, e.required_fields)
    except DatabaseConnectionError as e:
        return error_response("DATABASE_CONNECTION_ERROR", str(e))
    except Exception:
        logger.exception("employee-conflicts failed")
        return error_response("DATABASE_CONNECTION_ERROR", "Unable to connect to the database.")





# -------------------------------------------------------------------------
# Consolidated Scenarios Router (/api/v1/audits/*)
# -------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/audits", tags=["Audits"])

# One row per invoice from Invoice_Reconciliation_Flat, shared by 3-Way Discrepancy and Top Spend Concentration.
# The flat table is one row per invoice line and accounting split, and GrossAmount differs between the rows of
# one invoice (tax and non-item rows carry other values). The header row is therefore the first item line
# (_CatalogItem / _NonCatalogItem, lowest LineItem_Number), not LineItem_Number = 1, which 4k+ invoices lack.
# has_item_row = 0 means the invoice has no item line and GrossAmount came from a fallback row.
# Composing / Rejected / Denied / Canceled invoices are excluded. Credit memos are kept (negative GrossAmount).
_INVOICE_HEADER_CTE = """
    inv_ranked AS (
        SELECT Invoice_ID, InvoiceNumber, Supplier_ID, Supplier_Name,
            NULLIF(LTRIM(RTRIM(PONumber)), '') AS po_number, GrossAmount,
            COALESCE(TRY_CAST(InvoiceDate AS DATE), TRY_CAST(CreateDate AS DATE)) AS invoice_date,
            CASE WHEN LineType IN ('_CatalogItem', '_NonCatalogItem') THEN 1 ELSE 0 END AS has_item_row,
            ROW_NUMBER() OVER (
                PARTITION BY Invoice_ID
                ORDER BY CASE WHEN LineType IN ('_CatalogItem', '_NonCatalogItem') THEN 0 ELSE 1 END,
                         CASE WHEN LineItem_Number IS NULL THEN 1 ELSE 0 END,
                         LineItem_Number
            ) AS rn
        FROM dbo.Invoice_Reconciliation_Flat
        WHERE Invoice_ID IS NOT NULL
          AND GrossAmount IS NOT NULL
          AND COALESCE(InvoiceStatusString, '') NOT IN ('Composing', 'Rejected', 'Denied', 'Canceled')
    ),
    inv_hdr AS (
        SELECT * FROM inv_ranked WHERE rn = 1
    )
"""


@router.get("/approval-over-limits")
def get_approval_over_limits(filters: ApprovalOverLimitFilter = Query(default_factory=ApprovalOverLimitFilter)):
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH po_header AS (
        SELECT purchase_order_id AS purchase_order, created_by AS po_created_by, price_currency AS document_currency,
            SUM(TRY_CAST(REPLACE(REPLACE(REPLACE(price, ',', ''), '$', ''), ' ', '') AS DECIMAL(18, 2))) AS total_po_authorized_amount
        FROM [TicketSystemDBProd].[ticketsystem].[purchase_order_master]
        WHERE purchase_order_id IS NOT NULL AND purchase_order_id <> ''
        GROUP BY purchase_order_id, created_by, price_currency
    ),
    invoice_header AS (
        SELECT inv.invoice_id, inv.InvoiceNumber, inv.SupplierName, inv.PONumber, inv.user_id AS invoice_processed_by,
            TRY_CAST(inv.InvoiceDate AS DATE) AS invoice_date,
            MAX(TRY_CAST(REPLACE(REPLACE(REPLACE(COALESCE(NULLIF(inv.Total, ''), inv.AmountInclVAT, '0'), ',', ''), '$', ''), ' ', '') AS DECIMAL(18, 2))) AS total_invoiced_amount
        FROM dbo.Invoice_extracted_data inv
        INNER JOIN dbo.FileInput fi ON fi.pdf_id = inv.pdf_id
        WHERE inv.PONumber IS NOT NULL AND inv.PONumber <> ''
        GROUP BY inv.invoice_id, inv.InvoiceNumber, inv.SupplierName, inv.PONumber, inv.user_id, inv.InvoiceDate
    )
    SELECT inv.invoice_id, inv.InvoiceNumber AS invoice_number, inv.SupplierName AS supplier_name, inv.invoice_date,
        inv.PONumber AS po_number, po.po_created_by, inv.invoice_processed_by, po.document_currency AS currency,
        CAST(po.total_po_authorized_amount AS FLOAT) AS po_authorized_amount,
        CAST(inv.total_invoiced_amount AS FLOAT) AS invoice_total_amount,
        CAST((inv.total_invoiced_amount - po.total_po_authorized_amount) AS FLOAT) AS over_limit_amount,
        CAST(ROUND(((inv.total_invoiced_amount - po.total_po_authorized_amount) / NULLIF(po.total_po_authorized_amount, 0)) * 100, 2) AS FLOAT) AS percentage_over_limit
    FROM invoice_header inv
    INNER JOIN po_header po ON inv.PONumber = po.purchase_order
    WHERE inv.total_invoiced_amount > (po.total_po_authorized_amount * (1.0 + (COALESCE(?, 0.0) / 100.0)))
      AND (inv.total_invoiced_amount - po.total_po_authorized_amount) >= COALESCE(?, 0.0)
      AND (? IS NULL OR inv.SupplierName LIKE '%' + ? + '%')
      AND (? IS NULL OR inv.PONumber = ?)
      AND (? IS NULL OR inv.invoice_processed_by = ?)
      AND (? IS NULL OR po.po_created_by = ?)
      AND (? IS NULL OR inv.invoice_date >= ?)
      AND (? IS NULL OR inv.invoice_date <= ?)
    ORDER BY over_limit_amount DESC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.tolerance_pct,
        filters.min_excess,
        filters.supplier_name, filters.supplier_name,
        filters.po_number, filters.po_number,
        filters.invoice_processed_by, filters.invoice_processed_by,
        filters.po_created_by, filters.po_created_by,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


def _paged(filters: BasePaginatedFilter, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Standard paged response. A `total_count` column (COUNT(*) OVER ()) in the rows becomes the response total."""
    total = records[0].get("total_count") if records else None
    for r in records:
        r.pop("total_count", None)
    out: Dict[str, Any] = {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}
    if total is not None:
        out["total_count"] = total
    return out


# -------------------------------------------------------------------------
# Invoices Without PO Number (queries.md "Invoices Without PO Number")
# -------------------------------------------------------------------------
# Same rule as queries.md: header row (LineItem_Number = 1) with a NULL / blank PONumber. The count query and the
# detail query share one WHERE, so the total always matches the list.
# Additive: filters, invoice_date, violation_reason (constant, keeps the UI badge), OFFSET / FETCH paging.
# Not carried over: the old "PO_NOT_FOUND_IN_SAP" branch, it is not part of queries.md.
_PO_LESS_WHERE = """
WHERE LineItem_Number = 1
	AND (PONumber IS NULL OR LTRIM(RTRIM(PONumber)) = '')
	AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR Preparer = ?)
	AND (? IS NULL OR GrossAmount >= ?)
	AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) >= ?)
	AND (? IS NULL OR TRY_CAST(InvoiceDate AS DATE) <= ?)
"""

_PO_LESS_COUNT_SQL = (
    "SELECT COUNT(*) AS invoices_without_po FROM [Invoice_Reconciliation_Flat]" + _PO_LESS_WHERE
)

_PO_LESS_DETAIL_SQL = (
    """
SELECT
	Invoice_ID AS invoice_id,
	COALESCE(NULLIF(LTRIM(RTRIM(InvoiceNumber)), ''), Invoice_Name) AS invoice_number,
	Invoice_Name AS invoice_name,
	Supplier_Name AS supplier_name,
	CAST(GrossAmount AS FLOAT) AS invoice_total_amount,
	IsNonPO AS is_non_po,
	PONumber AS po_number,
	Requester AS requester,
	Preparer AS invoice_processed_by,
	TRY_CAST(InvoiceDate AS DATE) AS invoice_date,
	'MISSING_PO_NUMBER' AS violation_reason
FROM [Invoice_Reconciliation_Flat]"""
    + _PO_LESS_WHERE
    + """
ORDER BY GrossAmount DESC, Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""
)


@router.get("/po-less-invoices")
def get_po_less_invoices(filters: POLessInvoiceFilter = Query(default_factory=POLessInvoiceFilter)):
    offset = (filters.page - 1) * filters.page_size
    where_params = [
        filters.supplier_name or None, filters.supplier_name or None,
        filters.invoice_processed_by or None, filters.invoice_processed_by or None,
        filters.min_amount, filters.min_amount,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
    ]
    total = query(_PO_LESS_COUNT_SQL, where_params)[0]["invoices_without_po"]
    records = query(_PO_LESS_DETAIL_SQL, where_params + [offset, filters.page_size])
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records),
            "total_count": total, "data": records}


# -------------------------------------------------------------------------
# Retroactive POs (queries.md "Retroactive POs")
# -------------------------------------------------------------------------
# queries.md shape: invoice header row + PO creation date, flagged when the PO was created after the invoice date.
# DEVIATION D5: the PO date and the employee come from PR_mainData joined on PONumber = EP_ID, not from
#   purchase_order_master. Measured on the live DB: purchase_order_master.purchase_order_id matches 0 invoice POs,
#   date_created is a nightly load stamp (01:30), order_date is empty for 87% of rows and created_by has 5 values.
#   PR_mainData.Ordered_Date is the Ariba PO issue time (populated for 99.6% of POs), Requester / Approved_By are
#   the people behind the PR.
# DEVIATION D2: PR joined on EP_ID (queries.md joins ERP_PO_Number, which never matches).
# Additive: exclude_bot_invoices (FIVEBOT* preparers are back-loaded migration invoices).
_RETRO_SQL = """
WITH inv AS (
	SELECT
		Invoice_ID,
		InvoiceNumber,
		Invoice_Name,
		Supplier_Name,
		LTRIM(RTRIM(PONumber)) AS PONumber,
		GrossAmount,
		Requester,
		Preparer,
		COALESCE(TRY_CAST(InvoiceDate AS DATE), TRY_CAST(CreateDate AS DATE)) AS invoice_date
	FROM [Invoice_Reconciliation_Flat]
	WHERE LineItem_Number = 1
		AND PONumber IS NOT NULL
		AND LTRIM(RTRIM(PONumber)) <> ''
),
pr AS (
	-- one row per PR and PO, Ordered_Date = when the PO was issued
	SELECT
		PR_Number,
		NULLIF(LTRIM(RTRIM(EP_ID)), '') AS EP_ID,
		MAX(Requester)     AS PR_Requester,
		MAX(Approved_By)   AS PR_Approved_By,
		MAX(Approved_Date) AS PR_Approved_Date,
		MIN(TRY_CAST(Ordered_Date AS DATE)) AS po_creation_date
	FROM [PR_mainData]
	WHERE NULLIF(LTRIM(RTRIM(EP_ID)), '') IS NOT NULL
	GROUP BY PR_Number, NULLIF(LTRIM(RTRIM(EP_ID)), '')
)
SELECT
	inv.Invoice_ID AS invoice_id,
	COALESCE(NULLIF(LTRIM(RTRIM(inv.InvoiceNumber)), ''), inv.Invoice_Name) AS invoice_number,
	inv.Invoice_Name AS invoice_name,
	inv.Supplier_Name AS supplier_name,
	inv.PONumber AS po_number,
	CAST(inv.GrossAmount AS FLOAT) AS invoice_total_amount,
	inv.invoice_date,
	pr.po_creation_date,
	DATEDIFF(day, inv.invoice_date, pr.po_creation_date) AS days_po_created_after_invoice,
	pr.PR_Requester AS po_created_by,
	inv.Requester AS invoice_requester,
	inv.Preparer AS invoice_processed_by,
	pr.PR_Number AS pr_number,
	pr.PR_Approved_By AS pr_approved_by,
	pr.PR_Approved_Date AS pr_approved_date,
	COUNT(*) OVER () AS total_count
FROM inv
INNER JOIN pr ON pr.EP_ID = inv.PONumber
-- strict ">", a PO created on the same day as the invoice is not flagged
WHERE pr.po_creation_date > inv.invoice_date
	AND DATEDIFF(day, inv.invoice_date, pr.po_creation_date) >= COALESCE(?, 1)
	AND (? = 0 OR LEFT(UPPER(COALESCE(inv.Preparer, '')), 7) <> 'FIVEBOT')
	AND (? IS NULL OR inv.Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR inv.PONumber = ?)
	AND (? IS NULL OR pr.PR_Requester = ?)
	AND (? IS NULL OR inv.Preparer = ?)
	AND (? IS NULL OR inv.invoice_date >= ?)
	AND (? IS NULL OR inv.invoice_date <= ?)
ORDER BY days_po_created_after_invoice DESC, inv.invoice_date DESC, inv.Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/retroactive-pos")
def get_retroactive_pos(filters: RetroactivePOFilter = Query(default_factory=RetroactivePOFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.min_days_late,
        int(filters.exclude_bot_invoices),
        filters.supplier_name or None, filters.supplier_name or None,
        filters.po_number or None, filters.po_number or None,
        filters.created_by_user or None, filters.created_by_user or None,
        filters.invoice_processed_by or None, filters.invoice_processed_by or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_RETRO_SQL, params))


@router.get("/three-way-discrepancy")
def get_three_way_discrepancy(filters: ThreeWayDiscrepancyFilter = Query(default_factory=ThreeWayDiscrepancyFilter)):
    # PO vs invoice reconciliation from PR_mainData + Invoice_Reconciliation_Flat (no goods-receipt table is used).
    # Invoices join to PR_mainData on PONumber = EP_ID (ERP_PO_Number never matches). PO_line_item is often NULL,
    # so the comparison is per PO. PR values are tax-inclusive, so invoice GrossAmount is compared to PR Line_Total.
    # The check is cumulative per PO: all valid invoices billed against a PO are summed, credit memos net off.
    # Only over-billing is flagged, under-billing is normal while a PO is still being invoiced.
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH """ + _INVOICE_HEADER_CTE + """,
    pr_lines AS (
        -- PR_mainData is one row per PR line and cost-centre split, keep one Line_Total per PR line
        SELECT LTRIM(RTRIM(EP_ID)) AS po_number, PR_Number, Line_Number,
            MAX(Line_Total) AS line_total, MAX(Currency) AS currency
        FROM dbo.PR_mainData
        WHERE NULLIF(LTRIM(RTRIM(EP_ID)), '') IS NOT NULL
          AND COALESCE(Status, '') NOT IN ('Composing', 'Canceling')
        GROUP BY LTRIM(RTRIM(EP_ID)), PR_Number, Line_Number
    ),
    po AS (
        -- a few POs mix currencies, MAX(currency) is shown and no conversion is done
        SELECT po_number, SUM(line_total) AS po_total, MAX(currency) AS currency, MIN(PR_Number) AS pr_number
        FROM pr_lines
        GROUP BY po_number
    ),
    inv_by_po AS (
        -- invoices without an item line have an unreliable GrossAmount and are left out
        SELECT po_number, SUM(GrossAmount) AS invoiced_total, COUNT(DISTINCT Invoice_ID) AS invoice_count,
            MAX(invoice_date) AS last_invoice_date, MAX(Supplier_Name) AS supplier_name
        FROM inv_hdr
        WHERE has_item_row = 1 AND po_number IS NOT NULL
        GROUP BY po_number
    ),
    evaluated AS (
        SELECT i.po_number, po.pr_number, i.supplier_name, po.currency, i.invoice_count,
            CAST(i.invoiced_total AS FLOAT) AS invoiced_total,
            CAST(po.po_total AS FLOAT) AS po_total,
            CAST(i.invoiced_total - po.po_total AS FLOAT) AS amount_discrepancy,
            CAST(ROUND((i.invoiced_total - po.po_total) / NULLIF(po.po_total, 0) * 100.0, 2) AS FLOAT) AS discrepancy_pct,
            i.last_invoice_date
        FROM inv_by_po i
        INNER JOIN po ON po.po_number = i.po_number
        WHERE po.po_total IS NOT NULL
    )
    SELECT * FROM evaluated
    WHERE amount_discrepancy > COALESCE(?, 0.01)
      AND (? IS NULL OR supplier_name LIKE '%' + ? + '%')
      AND (? IS NULL OR po_number = ?)
      AND (? IS NULL OR last_invoice_date >= ?)
      AND (? IS NULL OR last_invoice_date <= ?)
    ORDER BY amount_discrepancy DESC, po_number ASC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.min_amount_discrepancy,
        filters.supplier_name, filters.supplier_name,
        filters.po_number, filters.po_number,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


@router.get("/po-invoice-utilization")
def get_po_invoice_utilization(filters: POUtilizationFilter = Query(default_factory=POUtilizationFilter)):
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH po_summary AS (
        SELECT purchase_order_id AS purchase_order, created_by AS po_created_by,
            MAX(supplier_name) AS supplier_name, price_currency AS document_currency,
            MIN(TRY_CAST(COALESCE(NULLIF(date_created, ''), order_date) AS DATE)) AS po_creation_date,
            SUM(TRY_CAST(REPLACE(REPLACE(REPLACE(price, ',', ''), '$', ''), ' ', '') AS DECIMAL(18, 2))) AS po_authorized_amount
        FROM [TicketSystemDBProd].[ticketsystem].[purchase_order_master]
        WHERE purchase_order_id IS NOT NULL AND purchase_order_id <> ''
        GROUP BY purchase_order_id, created_by, price_currency
    ),
    invoice_line AS (
        SELECT inv.invoice_id, LTRIM(RTRIM(inv.PONumber)) AS clean_po_number,
            TRY_CAST(inv.InvoiceDate AS DATE) AS invoice_date,
            MAX(TRY_CAST(REPLACE(REPLACE(REPLACE(COALESCE(NULLIF(inv.Total, ''), inv.AmountInclVAT, '0'), ',', ''), '$', ''), ' ', '') AS DECIMAL(18, 2))) AS invoice_total_amount
        FROM dbo.Invoice_extracted_data inv
        INNER JOIN dbo.FileInput fi ON fi.pdf_id = inv.pdf_id
        WHERE inv.PONumber IS NOT NULL AND LTRIM(RTRIM(inv.PONumber)) <> ''
        GROUP BY inv.invoice_id, LTRIM(RTRIM(inv.PONumber)), inv.InvoiceDate
    ),
    invoice_summary AS (
        SELECT clean_po_number AS purchase_order,
            COUNT(invoice_id) AS invoice_count,
            SUM(invoice_total_amount) AS total_invoiced_amount,
            MAX(invoice_date) AS last_invoice_date
        FROM invoice_line
        GROUP BY clean_po_number
    ),
    utilization AS (
        SELECT po.purchase_order AS po_number, po.supplier_name, po.po_created_by,
            po.document_currency AS currency, po.po_creation_date,
            CAST(po.po_authorized_amount AS FLOAT) AS po_authorized_amount,
            CAST(COALESCE(inv.total_invoiced_amount, 0) AS FLOAT) AS invoice_total_amount,
            CAST(COALESCE(inv.invoice_count, 0) AS INT) AS invoice_count,
            inv.last_invoice_date,
            CAST((po.po_authorized_amount - COALESCE(inv.total_invoiced_amount, 0)) AS FLOAT) AS remaining_amount,
            CAST(ROUND((COALESCE(inv.total_invoiced_amount, 0) / NULLIF(po.po_authorized_amount, 0)) * 100.0, 2) AS FLOAT) AS utilization_pct,
            CASE
                WHEN COALESCE(inv.total_invoiced_amount, 0) = 0 THEN 'NOT_UTILIZED'
                WHEN inv.total_invoiced_amount > po.po_authorized_amount THEN 'OVER_UTILIZED'
                WHEN inv.total_invoiced_amount >= po.po_authorized_amount * 0.9 THEN 'NEARLY_UTILIZED'
                ELSE 'PARTIALLY_UTILIZED'
            END AS utilization_status
        FROM po_summary po
        LEFT JOIN invoice_summary inv ON po.purchase_order = inv.purchase_order
    )
    SELECT * FROM utilization
    WHERE (? IS NULL OR po_number = ?)
      AND (? IS NULL OR supplier_name LIKE '%' + ? + '%')
      AND (? IS NULL OR po_created_by = ?)
      AND (? = 'ALL' OR ? IS NULL OR utilization_status = ?)
      AND (? IS NULL OR utilization_pct >= ?)
      AND (? IS NULL OR utilization_pct <= ?)
      AND (? IS NULL OR po_creation_date >= ?)
      AND (? IS NULL OR po_creation_date <= ?)
    ORDER BY utilization_pct DESC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.po_number, filters.po_number,
        filters.supplier_name, filters.supplier_name,
        filters.po_created_by, filters.po_created_by,
        filters.utilization_status or "ALL",
        filters.utilization_status,
        filters.utilization_status,
        filters.min_utilization_pct, filters.min_utilization_pct,
        filters.max_utilization_pct, filters.max_utilization_pct,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


@router.get("/top-spend-concentration")
def get_top_spend_concentration(filters: TopSpendFilter = Query(default_factory=TopSpendFilter)):
    # Supplier spend share from Invoice_Reconciliation_Flat: one header row per invoice, GrossAmount summed per
    # supplier (PO and non-PO invoices, credit memos net off). The amounts carry no currency and are treated as AED.
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH """ + _INVOICE_HEADER_CTE + """,
    keyed_invoices AS (
        SELECT Invoice_ID, GrossAmount, Supplier_Name, invoice_date,
            COALESCE(NULLIF(LTRIM(RTRIM(Supplier_ID)), ''), NULLIF(LTRIM(RTRIM(Supplier_Name)), '')) AS vendor_key
        FROM inv_hdr
    ),
    filtered_invoices AS (
        SELECT * FROM keyed_invoices
        WHERE vendor_key IS NOT NULL
          AND (? IS NULL OR invoice_date >= ?)
          AND (? IS NULL OR invoice_date <= ?)
    ),
    supplier_aggregates AS (
        SELECT vendor_key, MAX(Supplier_Name) AS supplier_name,
            COUNT(DISTINCT Invoice_ID) AS total_invoice_count,
            SUM(GrossAmount) AS supplier_total_spend,
            SUM(SUM(GrossAmount)) OVER () AS grand_total_spend
        FROM filtered_invoices
        GROUP BY vendor_key
    ),
    ranked_suppliers AS (
        SELECT supplier_name, total_invoice_count,
            CAST(supplier_total_spend AS FLOAT) AS supplier_total_spend,
            CAST(grand_total_spend AS FLOAT) AS grand_total_spend,
            CAST(ROUND((supplier_total_spend / NULLIF(grand_total_spend, 0)) * 100.0, 2) AS FLOAT) AS spend_percentage,
            CAST(ROUND((SUM(supplier_total_spend) OVER (ORDER BY supplier_total_spend DESC, vendor_key
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) / NULLIF(grand_total_spend, 0)) * 100.0, 2) AS FLOAT) AS cumulative_spend_pct,
            DENSE_RANK() OVER (ORDER BY supplier_total_spend DESC) AS spend_rank,
            vendor_key
        FROM supplier_aggregates
    )
    SELECT supplier_name, total_invoice_count, supplier_total_spend, grand_total_spend,
        spend_percentage, cumulative_spend_pct, spend_rank
    FROM ranked_suppliers
    WHERE (? IS NULL OR supplier_name LIKE '%' + ? + '%')
      AND (? IS NULL OR spend_percentage >= ?)
      AND (? IS NULL OR supplier_total_spend >= ?)
    ORDER BY spend_rank ASC, vendor_key ASC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        filters.supplier_name, filters.supplier_name,
        filters.min_spend_percentage, filters.min_spend_percentage,
        filters.min_spend_amount, filters.min_spend_amount,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


# Building blocks shared by the duplicate-family queries below.
_VALID_INVOICE = "COALESCE(InvoiceStatusString, '') NOT IN ('Composing', 'Rejected', 'Denied', 'Canceled')"

# The supplier's invoice number. InvoiceNumber is NULL on 39% of valid invoices (all the "Paying" ones), and
# Invoice_Name is unique per invoice, so neither can be used to compare invoices. Invoice_ID is "INV<number>-<seq>",
# the number is read back out of it (it matches InvoiceNumber on 99.5% of invoices that have both).
_INVOICE_REF_SQL = """COALESCE(NULLIF(LTRIM(RTRIM(InvoiceNumber)), ''),
		CASE WHEN CHARINDEX('-', REVERSE(Invoice_ID)) > 0
			THEN LEFT(SUBSTRING(Invoice_ID, 4, 500), LEN(SUBSTRING(Invoice_ID, 4, 500)) - CHARINDEX('-', REVERSE(Invoice_ID)))
			ELSE SUBSTRING(Invoice_ID, 4, 500) END)"""

# One header row per valid invoice, the item line first (LineItem_Number = 1 is missing on 4,280 invoices).
_INVOICE_REF_HEADER_CTE = f"""
hdr_ranked AS (
	SELECT Invoice_ID, Supplier_ID, Supplier_Name, GrossAmount,
		LOWER(LTRIM(RTRIM(Supplier_Name))) AS sup,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date,
		NULLIF(LTRIM(RTRIM(PONumber)), '') AS po_number,
		{_INVOICE_REF_SQL} AS invoice_ref,
		ROW_NUMBER() OVER (
			PARTITION BY Invoice_ID
			ORDER BY CASE WHEN LineType IN ('_CatalogItem', '_NonCatalogItem') THEN 0 ELSE 1 END,
				CASE WHEN LineItem_Number IS NULL THEN 1 ELSE 0 END,
				LineItem_Number
		) AS rn
	FROM dbo.Invoice_Reconciliation_Flat
	WHERE Invoice_ID IS NOT NULL
		AND GrossAmount IS NOT NULL
		AND {_VALID_INVOICE}
),
hdr AS (
	SELECT * FROM hdr_ranked WHERE rn = 1
)
"""

# Version order of a PR number ("PR123", "PR123-V2"), latest version first (same rule as po-line-duplicates).
_PR_VERSION_ORDER = """CASE WHEN CHARINDEX('-v', p.PR_Number) > 0
				THEN COALESCE(TRY_CAST(SUBSTRING(p.PR_Number, CHARINDEX('-v', p.PR_Number) + 2, 10) AS INT), 0)
				ELSE 0 END DESC,
			p.Last_Modified DESC"""


_FUZZY_CLEAN_CHARS = ["-", " ", "/", ".", "_", "#"]
_VARIANT_CLEAN_CHARS = ["-", " ", "/", ".", "_", "#", ",", ":", ";", "\\", "(", ")"]


def _clean_expr(column: str, chars: List[str]) -> str:
    """LOWER(REPLACE(REPLACE(column, c1, ''), c2, '')...) built from a list, so the nesting cannot go out of balance."""
    expr = column
    for c in chars:
        expr = f"REPLACE({expr}, '{c}', '')"
    return f"LOWER({expr})"


# -------------------------------------------------------------------------
# Exact Duplicates
# -------------------------------------------------------------------------
# DEVIATION D6: not the queries.md "Exact Duplicates" query. That one groups by Invoice_Name, which is unique per
# invoice, so it can never find a duplicate (0 rows on the live DB). This one compares the invoice content.
# An invoice is flagged when another valid invoice matches on the strongest of three tiers:
#   1 SAME_INVOICE_NUMBER            supplier + invoice number + gross amount
#   2 SAME_CONTENT_SAME_PO_DATE      supplier + PO + invoice date + net amount + line count + line fingerprint
#   3 SAME_CONTENT_SAME_DATE_NO_PO   the same without a PO, only invoices that carry no PO
# The fingerprint sums CHECKSUM(description, quantity, amount) over every item line, so two invoices only match when
# every line matches, quantity included. Net amount and line count sit in the key too, which makes a checksum
# collision need all three to collide.
# CONSEQUENCE: recurring bills (rent, insurance debit notes) repeat the same content on the same date, tier 3 is a
#   review list, not a verdict. Description is NULL on many lines and NULLs compare equal.
# charge_rank 1 is the earliest invoice of the group (the original), duplicate_exposure counts only the later copies.
_EXACT_DUP_SQL = f"""
WITH lines AS (
	-- one row per invoice line, the flat table has one row per accounting split
	SELECT DISTINCT Invoice_ID, LineItem_Number, LTRIM(RTRIM(Description)) AS descr, Quantity AS qty, Amount AS amt
	FROM dbo.Invoice_Reconciliation_Flat
	WHERE LineType IN ('_CatalogItem', '_NonCatalogItem')
		AND Quantity IS NOT NULL
		AND Amount IS NOT NULL
		AND {_VALID_INVOICE}
),
fp AS (
	SELECT Invoice_ID, COUNT(*) AS line_count, SUM(amt) AS net_amount,
		SUM(CAST(CHECKSUM(descr, qty, amt) AS BIGINT)) AS fingerprint
	FROM lines
	GROUP BY Invoice_ID
),
{_INVOICE_REF_HEADER_CTE},
j AS (
	SELECT h.*, f.line_count, f.net_amount, f.fingerprint
	FROM hdr h
	LEFT JOIN fp f ON f.Invoice_ID = h.Invoice_ID
),
tiers AS (
	SELECT Invoice_ID, 1 AS prio, 'SAME_INVOICE_NUMBER' AS match_type,
		MIN(Invoice_ID) OVER (PARTITION BY sup, invoice_ref, GrossAmount) AS group_id,
		COUNT(*) OVER (PARTITION BY sup, invoice_ref, GrossAmount) AS dup_count,
		ROW_NUMBER() OVER (PARTITION BY sup, invoice_ref, GrossAmount ORDER BY invoice_date, Invoice_ID) AS charge_rank
	FROM j
	WHERE sup IS NOT NULL AND invoice_ref <> ''
	UNION ALL
	SELECT Invoice_ID, 2, 'SAME_CONTENT_SAME_PO_DATE',
		MIN(Invoice_ID) OVER (PARTITION BY sup, po_number, invoice_date, net_amount, line_count, fingerprint),
		COUNT(*) OVER (PARTITION BY sup, po_number, invoice_date, net_amount, line_count, fingerprint),
		ROW_NUMBER() OVER (PARTITION BY sup, po_number, invoice_date, net_amount, line_count, fingerprint ORDER BY Invoice_ID)
	FROM j
	WHERE sup IS NOT NULL AND po_number IS NOT NULL AND invoice_date IS NOT NULL AND fingerprint IS NOT NULL
	UNION ALL
	SELECT Invoice_ID, 3, 'SAME_CONTENT_SAME_DATE_NO_PO',
		MIN(Invoice_ID) OVER (PARTITION BY sup, invoice_date, net_amount, line_count, fingerprint),
		COUNT(*) OVER (PARTITION BY sup, invoice_date, net_amount, line_count, fingerprint),
		ROW_NUMBER() OVER (PARTITION BY sup, invoice_date, net_amount, line_count, fingerprint ORDER BY Invoice_ID)
	FROM j
	WHERE sup IS NOT NULL AND po_number IS NULL AND invoice_date IS NOT NULL AND fingerprint IS NOT NULL
),
best AS (
	-- the strongest tier per invoice
	SELECT Invoice_ID, prio, match_type, group_id, dup_count, charge_rank,
		ROW_NUMBER() OVER (PARTITION BY Invoice_ID ORDER BY prio) AS rk
	FROM tiers
	WHERE dup_count > 1
)
SELECT
	j.Invoice_ID AS invoice_id,
	j.invoice_ref AS invoice_number,
	j.Supplier_Name AS supplier_name,
	COALESCE(NULLIF(LTRIM(RTRIM(j.Supplier_ID)), ''), j.Supplier_Name) AS vendor_key,
	j.po_number,
	j.invoice_date,
	CAST(j.GrossAmount AS FLOAT) AS invoice_total,
	j.line_count,
	b.match_type,
	b.group_id,
	b.dup_count,
	b.charge_rank,
	CAST(CASE WHEN b.charge_rank > 1 THEN j.GrossAmount ELSE 0 END AS FLOAT) AS duplicate_exposure,
	COUNT(*) OVER () AS total_count
FROM best b
INNER JOIN j ON j.Invoice_ID = b.Invoice_ID
WHERE b.rk = 1
	AND (? IS NULL OR j.Supplier_Name LIKE '%' + ? + '%'
		OR COALESCE(NULLIF(LTRIM(RTRIM(j.Supplier_ID)), ''), j.Supplier_Name) LIKE '%' + ? + '%')
	AND (? IS NULL OR j.invoice_ref = ?)
	AND (? IS NULL OR b.match_type = ?)
	AND (? IS NULL OR j.invoice_date >= ?)
	AND (? IS NULL OR j.invoice_date <= ?)
ORDER BY b.prio, b.group_id, b.charge_rank, j.Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/exact-duplicates")
def get_exact_duplicates(filters: ExactDuplicatesFilter = Query(default_factory=ExactDuplicatesFilter)):
    offset = (filters.page - 1) * filters.page_size
    vendor = filters.vendor_key or None
    params = [
        vendor, vendor, vendor,
        filters.invoice_number or None, filters.invoice_number or None,
        filters.match_type or None, filters.match_type or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_EXACT_DUP_SQL, params))


# -------------------------------------------------------------------------
# Fuzzy Duplicates (queries.md "Fuzzy Duplicates")
# -------------------------------------------------------------------------
# queries.md logic unchanged: header rows (LineItem_Number = 1), invoice number and invoice name with - space / . _ #
# stripped, grouped with supplier and gross amount, groups of 2+ are duplicates.
# Additive: invoice_date, MIN / MAX invoice number of the group, duplicate_exposure, filters, paging.
_FUZZY_SQL = f"""
WITH header AS (
	SELECT
		Supplier_Name,
		InvoiceNumber,
		GrossAmount,
		Invoice_Name,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date,
		{_clean_expr('InvoiceNumber', _FUZZY_CLEAN_CHARS)} AS clean_inv,
		{_clean_expr('Invoice_Name', _FUZZY_CLEAN_CHARS)} AS clean_inv_name
	FROM [Invoice_Reconciliation_Flat] inv
	WHERE LineItem_Number = 1
),
duplicates AS (
	SELECT
		COUNT(*) AS duplicates_count,
		Supplier_name,
		grossAmount,
		clean_inv,
		clean_inv_name,
		MIN(InvoiceNumber) AS invoice_number,
		MAX(InvoiceNumber) AS invoice_number_alt,
		MIN(invoice_date) AS invoice_date
	FROM header
	GROUP BY Supplier_name, grossAmount, clean_inv, clean_inv_name
)
SELECT
	duplicates_count AS dup_count,
	Supplier_name AS supplier_name,
	Supplier_name AS vendor_key,
	CAST(grossAmount AS FLOAT) AS invoice_total,
	clean_inv,
	clean_inv_name,
	invoice_number,
	invoice_number_alt,
	invoice_date,
	CAST(grossAmount * (duplicates_count - 1) AS FLOAT) AS duplicate_exposure,
	COUNT(*) OVER () AS total_count
FROM duplicates
WHERE duplicates_count > 1
	AND (? IS NULL OR Supplier_name LIKE '%' + ? + '%')
	AND (? IS NULL OR clean_inv LIKE '%' + ? + '%')
	AND (? IS NULL OR invoice_date >= ?)
	AND (? IS NULL OR invoice_date <= ?)
ORDER BY grossAmount DESC, Supplier_name, clean_inv
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/fuzzy-duplicates")
def get_fuzzy_duplicates(filters: FuzzyDuplicatesFilter = Query(default_factory=FuzzyDuplicatesFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.vendor_key or None, filters.vendor_key or None,
        filters.clean_inv or None, filters.clean_inv or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_FUZZY_SQL, params))


# -------------------------------------------------------------------------
# Round Payments (queries.md "Round Paymnets")
# -------------------------------------------------------------------------
# queries.md logic unchanged: header rows, whole-number gross amounts that are multiples of 100, tiered.
# Additive: the round_multiple filter (default = the queries.md rule, multiples of 100), vendor / amount / date
# filters, Invoice_ID and invoice_date in the output, paging.
_ROUND_SQL = """
WITH header AS (
	SELECT
		Invoice_ID,
		Supplier_Name,
		InvoiceNumber,
		Invoice_Name,
		PONumber,
		GrossAmount,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date
	FROM [Invoice_Reconciliation_Flat] inv
	WHERE LineItem_Number = 1
)
SELECT
	Invoice_ID AS invoice_id,
	Supplier_Name AS supplier_name,
	COALESCE(NULLIF(LTRIM(RTRIM(InvoiceNumber)), ''), Invoice_Name) AS invoice_number,
	Invoice_Name AS invoice_name,
	PONumber AS po_number,
	CAST(GrossAmount AS FLOAT) AS invoice_total,
	invoice_date,
	CASE
		WHEN CAST(GrossAmount AS BIGINT) % 100000 = 0 THEN 'Round 100,000'
		WHEN CAST(GrossAmount AS BIGINT) % 10000 = 0 THEN 'Round 10,000'
		WHEN CAST(GrossAmount AS BIGINT) % 1000 = 0 THEN 'Round 1,000'
		WHEN CAST(GrossAmount AS BIGINT) % 500 = 0 THEN 'Round 500'
		WHEN CAST(GrossAmount AS BIGINT) % 100 = 0 THEN 'Round 100'
	END AS round_category,
	COUNT(*) OVER () AS total_count
FROM header
WHERE GrossAmount <> 0
	AND GrossAmount = CAST(GrossAmount AS BIGINT)
	AND CAST(GrossAmount AS BIGINT) % COALESCE(?, 100) = 0
	AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR GrossAmount >= ?)
	AND (? IS NULL OR invoice_date >= ?)
	AND (? IS NULL OR invoice_date <= ?)
ORDER BY GrossAmount DESC, Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/round-payments")
def get_round_payments(filters: RoundPaymentsFilter = Query(default_factory=RoundPaymentsFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.round_multiple,
        filters.vendor_key or None, filters.vendor_key or None,
        filters.min_amount, filters.min_amount,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_ROUND_SQL, params))


# -------------------------------------------------------------------------
# Same PO line billed on different invoices (queries.md, under Exact Duplicates)
# -------------------------------------------------------------------------
# queries.md logic unchanged: the same PO line, supplier, quantity, amount and invoice date on 2+ different invoices.
# DEVIATION D2: the PR side is keyed on EP_ID, queries.md uses ERP_PO_Number, which never equals an invoice
#   PONumber (0 rows on the live DB, 442 with EP_ID).
# Additive: filters (applied after the duplicate test so a filter never breaks a group), paging.
_PO_LINE_SAME_CHARGE_SQL = """
WITH pr_lines AS (
	-- PR_mainData is one row per PR line, collapse it to one row per PO + PO line
	SELECT
		NULLIF(LTRIM(RTRIM(EP_ID)), '') AS PONumber,
		TRY_CAST(PO_line_item AS INT) AS PO_Line,
		MIN(PR_Number) AS PR_Number
	FROM [PR_mainData]
	WHERE NULLIF(LTRIM(RTRIM(EP_ID)), '') IS NOT NULL
		AND TRY_CAST(PO_line_item AS INT) IS NOT NULL
	GROUP BY NULLIF(LTRIM(RTRIM(EP_ID)), ''), TRY_CAST(PO_line_item AS INT)
),
inv_lines AS (
	-- DISTINCT: the flat table has one row per accounting split, a line with 2 splits would match itself
	SELECT DISTINCT
		Invoice_ID,
		InvoiceNumber,
		Invoice_Name,
		InvoiceStatusString,
		Supplier_Name,
		LOWER(LTRIM(RTRIM(Supplier_Name))) AS supplier_n,
		LTRIM(RTRIM(PONumber)) AS PONumber,
		TRY_CAST(POLineNumber AS INT) AS PO_Line,
		LineItem_Number,
		Description,
		Quantity,
		UnitPrice,
		Amount,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date
	FROM [Invoice_Reconciliation_Flat]
	WHERE PONumber IS NOT NULL
		AND LTRIM(RTRIM(PONumber)) <> ''
		AND COALESCE(InvoiceStatusString, '') NOT IN ('Composing', 'Rejected', 'Denied')
		AND Amount IS NOT NULL
		AND Amount <> 0
		AND TRY_CAST(InvoiceDate AS DATE) IS NOT NULL
),
joined AS (
	SELECT pr.PR_Number, l.*
	FROM inv_lines l
	INNER JOIN pr_lines pr
		ON pr.PONumber = l.PONumber
		AND pr.PO_Line = l.PO_Line
),
flagged AS (
	-- COUNT(DISTINCT) is not allowed in a window, MIN <> MAX of Invoice_ID means "2+ different invoices"
	SELECT
		*,
		COUNT(*) OVER (PARTITION BY PONumber, PO_Line, supplier_n, Quantity, Amount, invoice_date) AS line_count,
		MIN(Invoice_ID) OVER (PARTITION BY PONumber, PO_Line, supplier_n, Quantity, Amount, invoice_date) AS first_invoice,
		MAX(Invoice_ID) OVER (PARTITION BY PONumber, PO_Line, supplier_n, Quantity, Amount, invoice_date) AS last_invoice
	FROM joined
)
SELECT
	PONumber AS po_number,
	PO_Line AS po_line,
	PR_Number AS pr_number,
	Supplier_Name AS supplier_name,
	Invoice_ID AS invoice_id,
	InvoiceNumber AS invoice_number,
	Invoice_Name AS invoice_name,
	InvoiceStatusString AS invoice_status,
	invoice_date,
	LineItem_Number AS line_item_number,
	Description AS description,
	CAST(Quantity AS FLOAT) AS quantity,
	CAST(UnitPrice AS FLOAT) AS unit_price,
	CAST(Amount AS FLOAT) AS amount,
	line_count,
	COUNT(*) OVER () AS total_count
FROM flagged
WHERE first_invoice <> last_invoice
	AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR PONumber = ?)
	AND (? IS NULL OR invoice_date >= ?)
	AND (? IS NULL OR invoice_date <= ?)
ORDER BY Amount DESC, PONumber, PO_Line, invoice_date, Invoice_ID, LineItem_Number
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/po-line-same-charge")
def get_po_line_same_charge(filters: POLineSameChargeFilter = Query(default_factory=POLineSameChargeFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.supplier_name or None, filters.supplier_name or None,
        filters.po_number or None, filters.po_number or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_PO_LINE_SAME_CHARGE_SQL, params))


# -------------------------------------------------------------------------
# Same vendor, cleaned invoice number (queries.md, under Fuzzy Duplicates)
# -------------------------------------------------------------------------
# queries.md logic unchanged: the same vendor sending the same invoice number under a different spelling
# (INV-001, inv 001, INV/001), on POs that exist in PR_mainData.
# DEVIATION D1: queries.md nests only 11 REPLACE( for its 12 characters, so LOWER() receives 3 arguments and the
#   query fails to compile. The nesting is built from the character list here.
# DEVIATION D2: the PR side is keyed on EP_ID (queries.md: ERP_PO_Number, which never matches).
# Additive: filters (after the duplicate test), paging.
_VENDOR_VARIANTS_SQL = f"""
WITH pr_pos AS (
	SELECT DISTINCT NULLIF(LTRIM(RTRIM(EP_ID)), '') AS PONumber
	FROM [PR_mainData]
	WHERE NULLIF(LTRIM(RTRIM(EP_ID)), '') IS NOT NULL
),
inv AS (
	-- one row per invoice + PO, InvoiceNumber is often NULL so Invoice_Name is the fallback
	SELECT DISTINCT
		Invoice_ID,
		InvoiceNumber,
		Invoice_Name,
		Supplier_Name,
		LOWER(LTRIM(RTRIM(Supplier_Name))) AS supplier_n,
		LTRIM(RTRIM(PONumber)) AS PONumber,
		GrossAmount,
		InvoiceStatusString,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date,
		COALESCE(NULLIF(LTRIM(RTRIM(InvoiceNumber)), ''), Invoice_Name) AS inv_ref
	FROM [Invoice_Reconciliation_Flat]
	WHERE PONumber IS NOT NULL
		AND LTRIM(RTRIM(PONumber)) <> ''
		AND COALESCE(InvoiceStatusString, '') NOT IN ('Composing', 'Rejected', 'Denied')
),
cleaned AS (
	-- lowercase, then strip - space / . _ # , : ; \\ ( )
	SELECT
		inv.*,
		{_clean_expr('inv_ref', _VARIANT_CLEAN_CHARS)} AS clean_inv
	FROM inv
	INNER JOIN pr_pos ON pr_pos.PONumber = inv.PONumber
),
flagged AS (
	SELECT
		*,
		MIN(Invoice_ID) OVER (PARTITION BY supplier_n, clean_inv) AS first_invoice,
		MAX(Invoice_ID) OVER (PARTITION BY supplier_n, clean_inv) AS last_invoice,
		-- 1 = the raw numbers differ (a real re-key), 0 = the same text repeated
		CASE WHEN MIN(inv_ref) OVER (PARTITION BY supplier_n, clean_inv)
			<> MAX(inv_ref) OVER (PARTITION BY supplier_n, clean_inv) THEN 1 ELSE 0 END AS Raw_Numbers_Differ
	FROM cleaned
	WHERE clean_inv <> ''
)
SELECT
	Supplier_Name AS supplier_name,
	clean_inv,
	Raw_Numbers_Differ AS raw_numbers_differ,
	Invoice_ID AS invoice_id,
	InvoiceNumber AS invoice_number,
	Invoice_Name AS invoice_name,
	InvoiceStatusString AS invoice_status,
	PONumber AS po_number,
	invoice_date,
	CAST(GrossAmount AS FLOAT) AS invoice_total,
	COUNT(*) OVER () AS total_count
FROM flagged
WHERE first_invoice <> last_invoice
	AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR clean_inv LIKE '%' + ? + '%')
	AND (? IS NULL OR invoice_date >= ?)
	AND (? IS NULL OR invoice_date <= ?)
ORDER BY Raw_Numbers_Differ DESC, Supplier_Name, clean_inv, invoice_date, Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/vendor-invoice-variants")
def get_vendor_invoice_variants(
    filters: VendorInvoiceVariantsFilter = Query(default_factory=VendorInvoiceVariantsFilter),
):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.supplier_name or None, filters.supplier_name or None,
        filters.clean_inv or None, filters.clean_inv or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_VENDOR_VARIANTS_SQL, params))


# -------------------------------------------------------------------------
# PO line over-billed (new KPI)
# -------------------------------------------------------------------------
# What was billed on one PO line (valid invoices, item lines, amount + line tax) is above the PO line total in
# PR_mainData (latest PR version, AED only, PR values are tax-inclusive so the tolerance absorbs rounding).
# repeated_line_in_invoice = one invoice lists the same PO line twice with the same quantity and amount, the pattern
# behind the biggest cases (billed quantity exactly 2x the ordered quantity).
# CONSEQUENCE: non-AED PR lines (about 1.8%, mostly CHF) are skipped, no currency conversion is done. Lines whose PO
#   has no PR, or whose PO_line_item does not line up with POLineNumber (about 1.7%), are not compared.
_PO_LINE_OVERBILLED_SQL = f"""
WITH pr AS (
	SELECT po_number, po_line, pr_number, ordered_qty, po_line_total, item_description
	FROM (
		SELECT
			LTRIM(RTRIM(p.EP_ID)) AS po_number,
			p.PO_line_item AS po_line,
			p.PR_Number AS pr_number,
			TRY_CAST(p.Quantity AS DECIMAL(18, 4)) AS ordered_qty,
			TRY_CAST(p.Line_Total AS DECIMAL(18, 2)) AS po_line_total,
			p.Item_Description AS item_description,
			ROW_NUMBER() OVER (
				PARTITION BY LTRIM(RTRIM(p.EP_ID)), p.PO_line_item
				ORDER BY {_PR_VERSION_ORDER}
			) AS rn
		FROM dbo.PR_mainData p
		WHERE NULLIF(LTRIM(RTRIM(p.EP_ID)), '') IS NOT NULL
			AND p.PO_line_item IS NOT NULL
			AND COALESCE(p.Currency, 'AED') = 'AED'
	) x
	WHERE rn = 1 AND po_line_total > 0
),
lines AS (
	SELECT DISTINCT
		Invoice_ID, LineItem_Number,
		LTRIM(RTRIM(PONumber)) AS po_number,
		POLineNumber AS po_line,
		Quantity, Amount,
		COALESCE(Amount, 0) + COALESCE(Line_Tax, 0) AS gross_line,
		Supplier_Name,
		TRY_CAST(InvoiceDate AS DATE) AS invoice_date
	FROM dbo.Invoice_Reconciliation_Flat
	WHERE LineType IN ('_CatalogItem', '_NonCatalogItem')
		AND PONumber IS NOT NULL
		AND LTRIM(RTRIM(PONumber)) <> ''
		AND POLineNumber IS NOT NULL
		AND {_VALID_INVOICE}
),
repeated AS (
	SELECT DISTINCT Invoice_ID, po_number, po_line
	FROM (
		SELECT Invoice_ID, po_number, po_line,
			COUNT(*) OVER (PARTITION BY Invoice_ID, po_number, po_line, Quantity, Amount) AS same_lines
		FROM lines
	) x
	WHERE same_lines > 1
),
il AS (
	SELECT l.po_number, l.po_line,
		SUM(l.gross_line) AS billed_gross,
		SUM(l.Quantity) AS billed_qty,
		COUNT(DISTINCT l.Invoice_ID) AS invoice_count,
		MAX(l.invoice_date) AS last_invoice_date,
		MAX(l.Supplier_Name) AS supplier_name,
		MAX(CASE WHEN r.Invoice_ID IS NOT NULL THEN 1 ELSE 0 END) AS repeated_line_in_invoice
	FROM lines l
	LEFT JOIN repeated r
		ON r.Invoice_ID = l.Invoice_ID AND r.po_number = l.po_number AND r.po_line = l.po_line
	GROUP BY l.po_number, l.po_line
)
SELECT
	il.po_number,
	il.po_line,
	pr.pr_number,
	il.supplier_name,
	pr.item_description,
	CAST(pr.ordered_qty AS FLOAT) AS ordered_qty,
	CAST(il.billed_qty AS FLOAT) AS billed_qty,
	CAST(pr.po_line_total AS FLOAT) AS po_line_total,
	CAST(il.billed_gross AS FLOAT) AS billed_gross,
	CAST(il.billed_gross - pr.po_line_total AS FLOAT) AS over_billed_amount,
	CAST(ROUND((il.billed_gross - pr.po_line_total) / pr.po_line_total * 100.0, 2) AS FLOAT) AS over_pct,
	il.invoice_count,
	il.repeated_line_in_invoice,
	il.last_invoice_date,
	COUNT(*) OVER () AS total_count
FROM il
INNER JOIN pr ON pr.po_number = il.po_number AND pr.po_line = il.po_line
WHERE il.billed_gross > pr.po_line_total * (1.0 + COALESCE(?, 5.0) / 100.0)
	AND il.billed_gross - pr.po_line_total >= COALESCE(?, 100.0)
	AND (? = 0 OR il.repeated_line_in_invoice = 1)
	AND (? IS NULL OR il.supplier_name LIKE '%' + ? + '%')
	AND (? IS NULL OR il.po_number = ?)
	AND (? IS NULL OR il.last_invoice_date >= ?)
	AND (? IS NULL OR il.last_invoice_date <= ?)
ORDER BY over_billed_amount DESC, il.po_number, il.po_line
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/po-line-overbilled")
def get_po_line_overbilled(filters: POLineOverbilledFilter = Query(default_factory=POLineOverbilledFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.tolerance_pct,
        filters.min_excess,
        int(filters.repeated_only),
        filters.supplier_name or None, filters.supplier_name or None,
        filters.po_number or None, filters.po_number or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_PO_LINE_OVERBILLED_SQL, params))


# -------------------------------------------------------------------------
# Invoice number reused with a different amount (new KPI)
# -------------------------------------------------------------------------
# The same supplier and the same invoice number on 2+ valid invoices whose gross amounts differ: a supplier re-using
# a number to push a changed amount through. Same invoice reference and header rules as Exact Duplicates.
# CONSEQUENCE: the supplier is matched on the trimmed, lower-cased Supplier_Name, the same company spelled two ways
#   is missed.
_INVOICE_REUSE_SQL = f"""
WITH {_INVOICE_REF_HEADER_CTE},
grp AS (
	SELECT *,
		COUNT(*) OVER (PARTITION BY sup, invoice_ref) AS dup_count,
		MIN(GrossAmount) OVER (PARTITION BY sup, invoice_ref) AS min_total,
		MAX(GrossAmount) OVER (PARTITION BY sup, invoice_ref) AS max_total
	FROM hdr
	WHERE sup IS NOT NULL AND invoice_ref <> ''
)
SELECT
	Invoice_ID AS invoice_id,
	invoice_ref AS invoice_number,
	Supplier_Name AS supplier_name,
	po_number,
	invoice_date,
	CAST(GrossAmount AS FLOAT) AS invoice_total,
	dup_count,
	CAST(min_total AS FLOAT) AS min_total,
	CAST(max_total AS FLOAT) AS max_total,
	CAST(max_total - min_total AS FLOAT) AS amount_spread,
	COUNT(*) OVER () AS total_count
FROM grp
WHERE dup_count > 1
	AND min_total <> max_total
	AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
	AND (? IS NULL OR invoice_ref = ?)
	AND (? IS NULL OR invoice_date >= ?)
	AND (? IS NULL OR invoice_date <= ?)
ORDER BY amount_spread DESC, sup, invoice_ref, invoice_date, Invoice_ID
OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
"""


@router.get("/invoice-number-reuse")
def get_invoice_number_reuse(filters: InvoiceNumberReuseFilter = Query(default_factory=InvoiceNumberReuseFilter)):
    offset = (filters.page - 1) * filters.page_size
    params = [
        filters.supplier_name or None, filters.supplier_name or None,
        filters.invoice_number or None, filters.invoice_number or None,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    return _paged(filters, query(_INVOICE_REUSE_SQL, params))


@router.get("/weekend-payments")
def get_weekend_payments(filters: WeekendPaymentsFilter = Query(default_factory=WeekendPaymentsFilter)):
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH header AS (
        SELECT Invoice_ID, InvoiceNumber, Supplier_Name, Supplier_ID, GrossAmount AS Invoice_Total, InvoiceDate, CreateDate,
            COALESCE(NULLIF(LTRIM(RTRIM(Supplier_ID)), ''), Supplier_Name) AS vendor_key,
            ROW_NUMBER() OVER (PARTITION BY Invoice_ID ORDER BY Invoice_ID) AS rn
        FROM dbo.Invoice_Reconciliation_Flat
    ),
    dedup AS (
        SELECT * FROM header WHERE rn = 1
    )
    SELECT Invoice_ID AS pdf_id, vendor_key, InvoiceNumber AS invoice_number, Supplier_Name AS supplier_name,
        Invoice_Total AS invoice_total, InvoiceDate AS invoice_date, CreateDate AS created_at,
        DATENAME(WEEKDAY, TRY_CONVERT(date, CreateDate)) AS day_of_week
    FROM dedup
    WHERE CreateDate IS NOT NULL
      AND DATEDIFF(DAY, 0, TRY_CONVERT(date, CreateDate)) % 7 IN (5, 6)
      AND (? IS NULL OR vendor_key LIKE '%' + ? + '%')
      AND (? IS NULL OR TRY_CONVERT(date, CreateDate) >= ?)
      AND (? IS NULL OR TRY_CONVERT(date, CreateDate) <= ?)
    ORDER BY CreateDate DESC
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.vendor_key, filters.vendor_key,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


@router.get("/po-line-duplicates")
def get_po_line_duplicates(filters: PODuplicateChargeFilter = Query(default_factory=PODuplicateChargeFilter)):
    """Same PO line billed on 2+ invoices with different invoice numbers (same quantity and unit price)."""
    offset = (filters.page - 1) * filters.page_size
    sql = """
    WITH pr_src AS (
        -- one row per PR line and PR version, keyed by both PO ids (SAP PO number and Ariba order id)
        SELECT
            LTRIM(RTRIM(k.po_key))                   AS po_number,
            p.PO_line_item                           AS po_line,
            p.PR_Number                              AS pr_number,
            TRY_CAST(p.Quantity   AS DECIMAL(18, 4)) AS ordered_qty,
            TRY_CAST(p.Unit_Price AS DECIMAL(18, 2)) AS ordered_unit_price,
            p.Item_Description                       AS item_description,
            p.ItemCategory                           AS item_category,
            ROW_NUMBER() OVER (
                PARTITION BY LTRIM(RTRIM(k.po_key)), p.PO_line_item
                ORDER BY
                    CASE WHEN CHARINDEX('-v', p.PR_Number) > 0
                        THEN COALESCE(TRY_CAST(SUBSTRING(p.PR_Number, CHARINDEX('-v', p.PR_Number) + 2, 10) AS INT), 0)
                        ELSE 0 END DESC,
                    p.Last_Modified DESC
            )                                        AS rn
        FROM dbo.PR_mainData p
        CROSS APPLY (VALUES (p.ERP_PO_Number), (p.EP_ID)) AS k(po_key)
        WHERE k.po_key IS NOT NULL
            AND LTRIM(RTRIM(k.po_key)) <> ''
            AND p.PO_line_item IS NOT NULL
    ),
    pr AS (
        -- latest PR version per PO line
        SELECT * FROM pr_src WHERE rn = 1
    ),
    inv AS (
        -- line level: every billed line of a PO invoice, no status filter
        SELECT
            Invoice_ID,
            COALESCE(NULLIF(LTRIM(RTRIM(InvoiceNumber)), ''),
                NULLIF(LTRIM(RTRIM(Invoice_Name)), ''),
                CAST(Invoice_ID AS NVARCHAR(500)))                                AS invoice_ref,
            Supplier_ID,
            Supplier_Name,
            LTRIM(RTRIM(PONumber))                                                AS po_number,
            POLineNumber                                                          AS po_line,
            LineType,
            TRY_CAST(Quantity  AS DECIMAL(18, 4))                                 AS qty,
            -- DEVIATION D3: UnitPrice is NULL on every row of the flat table (500,931 of 500,931), so the query as
            --   written in queries.md can never return a row. The unit price is derived as Amount / Quantity.
            COALESCE(NULLIF(TRY_CAST(UnitPrice AS DECIMAL(18, 2)), 0),
                TRY_CAST(Amount AS DECIMAL(18, 2)) / NULLIF(TRY_CAST(Quantity AS DECIMAL(18, 4)), 0)) AS unit_price,
            TRY_CAST(Amount    AS DECIMAL(18, 2))                                 AS line_amount,
            COALESCE(TRY_CAST(InvoiceDate AS DATE), TRY_CAST(CreateDate AS DATE)) AS invoice_date,
            CreateDate,
            InvoiceStatusString,
            IR_StatusString,
            Payment_StatusString,
            Payment_ID
        FROM dbo.Invoice_Reconciliation_Flat
        WHERE PONumber IS NOT NULL
            AND LTRIM(RTRIM(PONumber)) <> ''
            AND POLineNumber IS NOT NULL
            AND TRY_CAST(Quantity  AS DECIMAL(18, 4)) > 0
            AND COALESCE(NULLIF(TRY_CAST(UnitPrice AS DECIMAL(18, 2)), 0),
                TRY_CAST(Amount AS DECIMAL(18, 2)) / NULLIF(TRY_CAST(Quantity AS DECIMAL(18, 4)), 0)) > 0
            AND (? IS NULL OR Supplier_Name LIKE '%' + ? + '%')
            AND (? IS NULL OR LTRIM(RTRIM(PONumber)) = ?)
    ),
    hit AS (
        -- attach the ordered requirement to every billed line of that PO line
        SELECT inv.*, pr.pr_number, pr.ordered_qty, pr.ordered_unit_price, pr.item_description, pr.item_category
        FROM inv
        INNER JOIN pr
            ON pr.po_number = inv.po_number
            AND pr.po_line  = inv.po_line
    ),
    -- Speed only, same rows as before: hit is read once. The old grp / line_total / flagged CTEs each re-read hit,
    -- so the PR ranking above was evaluated three times (157 s), the window functions below evaluate it once.
    w1 AS (
        SELECT
            hit.*,
            DENSE_RANK() OVER (PARTITION BY po_number, po_line, qty, unit_price ORDER BY Invoice_ID) AS inv_rank,
            -- MIN <> MAX means 2+ distinct invoice numbers (COUNT(DISTINCT) is not allowed in a window)
            MIN(invoice_ref) OVER (PARTITION BY po_number, po_line, qty, unit_price) AS min_ref,
            MAX(invoice_ref) OVER (PARTITION BY po_number, po_line, qty, unit_price) AS max_ref,
            -- everything billed on the PO line, compared with the ordered quantity
            SUM(qty) OVER (PARTITION BY po_number, po_line) AS total_invoiced_qty
        FROM hit
    ),
    w2 AS (
        -- the highest dense rank of a group is its number of distinct invoices
        SELECT w1.*, MAX(inv_rank) OVER (PARTITION BY po_number, po_line, qty, unit_price) AS dup_count
        FROM w1
    ),
    flagged AS (
        -- same PO + PO line + quantity + unit price on 2+ invoices with different invoice numbers
        SELECT
            h.po_number,
            h.po_line,
            h.pr_number,
            h.invoice_ref                                                       AS invoice_number,
            h.Invoice_ID                                                        AS invoice_id,
            h.Supplier_Name                                                     AS supplier_name,
            COALESCE(NULLIF(LTRIM(RTRIM(h.Supplier_ID)), ''), h.Supplier_Name)  AS vendor_key,
            h.invoice_date,
            h.CreateDate                                                        AS created_at,
            h.item_description,
            h.item_category,
            h.LineType                                                          AS line_type,
            h.ordered_qty,
            h.ordered_unit_price,
            h.qty                                                               AS quantity,
            h.unit_price,
            h.line_amount,
            h.dup_count,
            DENSE_RANK() OVER (
                PARTITION BY h.po_number, h.po_line, h.qty, h.unit_price
                ORDER BY h.invoice_date, h.Invoice_ID
            )                                                                   AS charge_rank,
            DATEDIFF(day,
                MIN(h.invoice_date) OVER (PARTITION BY h.po_number, h.po_line, h.qty, h.unit_price),
                MAX(h.invoice_date) OVER (PARTITION BY h.po_number, h.po_line, h.qty, h.unit_price)
            )                                                                   AS days_apart,
            h.total_invoiced_qty,
            CASE WHEN h.total_invoiced_qty > h.ordered_qty
                THEN h.total_invoiced_qty - h.ordered_qty ELSE 0 END            AS over_billed_qty,
            h.InvoiceStatusString,
            h.IR_StatusString,
            h.Payment_StatusString,
            h.Payment_ID
        FROM w2 h
        WHERE h.dup_count > 1
            AND h.min_ref <> h.max_ref
    )
    SELECT po_number, po_line, pr_number, invoice_number, invoice_id, supplier_name, vendor_key,
        invoice_date, created_at, item_description, item_category, line_type,
        CAST(ordered_qty AS FLOAT) AS ordered_qty,
        CAST(ordered_unit_price AS FLOAT) AS ordered_unit_price,
        CAST(quantity AS FLOAT) AS quantity,
        CAST(unit_price AS FLOAT) AS unit_price,
        CAST(line_amount AS FLOAT) AS line_amount,
        dup_count, charge_rank, days_apart,
        CAST(total_invoiced_qty AS FLOAT) AS total_invoiced_qty,
        CAST(over_billed_qty AS FLOAT) AS over_billed_qty,
        InvoiceStatusString AS invoice_status,
        IR_StatusString AS ir_status,
        Payment_StatusString AS payment_status,
        Payment_ID AS payment_id,
        CAST(CASE WHEN charge_rank > 1 THEN line_amount ELSE 0 END AS FLOAT) AS duplicate_exposure
    FROM flagged
    WHERE (? IS NULL OR invoice_date >= ?)
      AND (? IS NULL OR invoice_date <= ?)
    ORDER BY po_number, po_line, charge_rank, invoice_id
    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
    """
    params = [
        filters.supplier_name, filters.supplier_name,
        filters.po_number, filters.po_number,
        filters.start_date, filters.start_date,
        filters.end_date, filters.end_date,
        offset,
        filters.page_size,
    ]
    records = query(sql, params)
    return {"page": filters.page, "page_size": filters.page_size, "count": len(records), "data": records}


app.include_router(router)




# -------------------------------------------------------------------------
# Entrypoint Runner
# -------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("audit_dashboard:app", host="0.0.0.0", port=8000, reload=True)