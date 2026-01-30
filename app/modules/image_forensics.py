"""
Image Forensics Module
CyberTrace - Zambia Police Service

Image and document forensic analysis including EXIF extraction,
GPS coordinate mapping, Error Level Analysis (ELA), OCR placeholder,
and document metadata extraction.
"""

import os
import io
import time
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger('osint')


class ImageForensics:
    """Image and Document Forensic Analysis Tool"""

    def __init__(self):
        self.results = {
            'file_path': None,
            'file_type': None,
            'file_hash': {},
            'exif_data': {},
            'gps_data': {},
            'location_name': None,
            'ela_results': {},
            'ocr_text': None,
            'document_metadata': {},
            'risk_score': 0,
            'risk_factors': [],
            'metadata': {
                'analyzed_at': None,
                'analysis_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def analyze_image(self, file_path: str) -> Dict:
        """
        Main orchestrator for image forensic analysis.

        Args:
            file_path: Path to the image file

        Returns:
            Dict with comprehensive image analysis results
        """
        self.start_time = time.time()
        self.results['file_path'] = file_path
        self.results['metadata']['analyzed_at'] = datetime.utcnow().isoformat()

        # Determine file type
        ext = os.path.splitext(file_path)[1].lower()
        self.results['file_type'] = ext

        # File hashes for integrity
        try:
            self.results['file_hash'] = self._calculate_file_hashes(file_path)
        except Exception as e:
            logger.error(f"File hash calculation failed: {e}")
            self.results['file_hash'] = {'error': str(e)}

        # Step 1: EXIF extraction
        try:
            self.results['exif_data'] = self.extract_exif(file_path)
        except Exception as e:
            logger.error(f"EXIF extraction failed for {file_path}: {e}")
            self.results['exif_data'] = {'error': str(e)}

        # Step 2: GPS data extraction
        try:
            self.results['gps_data'] = self.extract_gps(self.results['exif_data'])
        except Exception as e:
            logger.error(f"GPS extraction failed for {file_path}: {e}")
            self.results['gps_data'] = {'error': str(e)}

        # Step 3: Reverse geocode GPS coordinates
        try:
            lat = self.results['gps_data'].get('latitude')
            lon = self.results['gps_data'].get('longitude')
            if lat and lon:
                self.results['location_name'] = self.get_location_name(lat, lon)
        except Exception as e:
            logger.error(f"Reverse geocoding failed: {e}")
            self.results['location_name'] = None

        # Step 4: Error Level Analysis
        try:
            if ext in ('.jpg', '.jpeg', '.png', '.bmp', '.tiff'):
                self.results['ela_results'] = self.error_level_analysis(file_path)
        except Exception as e:
            logger.error(f"ELA failed for {file_path}: {e}")
            self.results['ela_results'] = {'error': str(e)}

        # Step 5: OCR placeholder
        try:
            self.results['ocr_text'] = self.extract_text_ocr(file_path)
        except Exception as e:
            logger.error(f"OCR failed for {file_path}: {e}")
            self.results['ocr_text'] = None

        # Step 6: Risk score
        try:
            risk_data = self.calculate_risk_score(self.results)
            self.results['risk_score'] = risk_data['score']
            self.results['risk_factors'] = risk_data['factors']
        except Exception as e:
            logger.error(f"Risk calculation failed: {e}")

        # Finalize metadata
        self.results['metadata']['analysis_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def _calculate_file_hashes(self, file_path: str) -> Dict:
        """Calculate MD5, SHA1, and SHA256 hashes for a file."""
        hashes = {
            'md5': None,
            'sha1': None,
            'sha256': None,
            'file_size': None
        }

        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            file_size = 0
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    file_size += len(chunk)

            hashes['md5'] = md5.hexdigest()
            hashes['sha1'] = sha1.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
            hashes['file_size'] = file_size
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")

        return hashes

    def extract_exif(self, file_path: str) -> Dict:
        """
        Extract EXIF data from an image file using Pillow.

        Args:
            file_path: Path to the image file

        Returns:
            Dict with EXIF metadata
        """
        exif_data = {
            'camera_make': None,
            'camera_model': None,
            'software': None,
            'datetime_original': None,
            'datetime_digitized': None,
            'datetime_modified': None,
            'exposure_time': None,
            'f_number': None,
            'iso_speed': None,
            'focal_length': None,
            'flash': None,
            'image_width': None,
            'image_height': None,
            'orientation': None,
            'gps_info': {},
            'all_tags': {},
            'error': None
        }

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            img = Image.open(file_path)
            exif_data['image_width'] = img.width
            exif_data['image_height'] = img.height

            raw_exif = img._getexif()
            if raw_exif is None:
                exif_data['error'] = 'No EXIF data found'
                return exif_data

            for tag_id, value in raw_exif.items():
                tag_name = TAGS.get(tag_id, tag_id)

                # Convert bytes to string for serialization
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace')
                    except Exception:
                        value = str(value)

                # Map specific tags
                if tag_name == 'Make':
                    exif_data['camera_make'] = str(value)
                elif tag_name == 'Model':
                    exif_data['camera_model'] = str(value)
                elif tag_name == 'Software':
                    exif_data['software'] = str(value)
                elif tag_name == 'DateTimeOriginal':
                    exif_data['datetime_original'] = str(value)
                elif tag_name == 'DateTimeDigitized':
                    exif_data['datetime_digitized'] = str(value)
                elif tag_name == 'DateTime':
                    exif_data['datetime_modified'] = str(value)
                elif tag_name == 'ExposureTime':
                    exif_data['exposure_time'] = str(value)
                elif tag_name == 'FNumber':
                    exif_data['f_number'] = float(value) if value else None
                elif tag_name == 'ISOSpeedRatings':
                    exif_data['iso_speed'] = value
                elif tag_name == 'FocalLength':
                    exif_data['focal_length'] = float(value) if value else None
                elif tag_name == 'Flash':
                    exif_data['flash'] = value
                elif tag_name == 'Orientation':
                    exif_data['orientation'] = value
                elif tag_name == 'GPSInfo':
                    gps_info = {}
                    if isinstance(value, dict):
                        for gps_tag_id, gps_value in value.items():
                            gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag_name] = gps_value
                    exif_data['gps_info'] = gps_info

                # Store all tags
                try:
                    exif_data['all_tags'][str(tag_name)] = str(value)
                except Exception:
                    pass

        except ImportError:
            exif_data['error'] = 'Pillow library not available'
            logger.error("Pillow is required for EXIF extraction")
        except Exception as e:
            exif_data['error'] = f'EXIF extraction failed: {str(e)}'
            logger.error(f"EXIF extraction error for {file_path}: {e}")

        return exif_data

    def extract_gps(self, exif_data: Dict) -> Dict:
        """
        Convert GPS EXIF tags to decimal latitude/longitude.

        Args:
            exif_data: EXIF data dict with gps_info

        Returns:
            Dict with decimal latitude and longitude
        """
        gps_data = {
            'latitude': None,
            'longitude': None,
            'altitude': None,
            'has_gps': False,
            'error': None
        }

        gps_info = exif_data.get('gps_info', {})
        if not gps_info:
            return gps_data

        try:
            # Extract latitude
            lat = gps_info.get('GPSLatitude')
            lat_ref = gps_info.get('GPSLatitudeRef', 'N')

            # Extract longitude
            lon = gps_info.get('GPSLongitude')
            lon_ref = gps_info.get('GPSLongitudeRef', 'E')

            if lat and lon:
                lat_decimal = self._dms_to_decimal(lat, lat_ref)
                lon_decimal = self._dms_to_decimal(lon, lon_ref)

                gps_data['latitude'] = lat_decimal
                gps_data['longitude'] = lon_decimal
                gps_data['has_gps'] = True

            # Extract altitude
            alt = gps_info.get('GPSAltitude')
            alt_ref = gps_info.get('GPSAltitudeRef', 0)
            if alt is not None:
                altitude = float(alt)
                if alt_ref == 1:  # Below sea level
                    altitude = -altitude
                gps_data['altitude'] = altitude

        except Exception as e:
            gps_data['error'] = f'GPS extraction failed: {str(e)}'
            logger.error(f"GPS data extraction error: {e}")

        return gps_data

    def _dms_to_decimal(self, dms, ref: str) -> float:
        """Convert DMS (degrees, minutes, seconds) to decimal degrees."""
        try:
            degrees = float(dms[0])
            minutes = float(dms[1])
            seconds = float(dms[2])

            decimal = degrees + minutes / 60 + seconds / 3600

            if ref in ('S', 'W'):
                decimal = -decimal

            return round(decimal, 7)
        except (TypeError, IndexError, ValueError) as e:
            logger.error(f"DMS conversion error: {e}")
            return 0.0

    def get_location_name(self, lat: float, lon: float) -> Optional[str]:
        """
        Reverse geocode coordinates to a location name using geopy Nominatim.

        Args:
            lat: Latitude
            lon: Longitude

        Returns:
            Location name string or None
        """
        try:
            from geopy.geocoders import Nominatim

            geolocator = Nominatim(user_agent='CyberTrace-ZambiaPolice')
            location = geolocator.reverse(f'{lat}, {lon}', timeout=10)
            self.api_calls += 1

            if location:
                return location.address
        except ImportError:
            logger.debug("geopy not available for reverse geocoding")
        except Exception as e:
            logger.error(f"Reverse geocoding error: {e}")

        return None

    def error_level_analysis(self, file_path: str) -> Dict:
        """
        Perform Error Level Analysis (ELA) on an image.
        Detects potential image manipulation by re-saving at a known quality
        and comparing with the original.

        Args:
            file_path: Path to the image file

        Returns:
            Dict with ELA results
        """
        ela_results = {
            'performed': False,
            'max_difference': 0,
            'mean_difference': 0,
            'suspicious_regions': 0,
            'manipulation_likelihood': 'unknown',
            'ela_image_path': None,
            'error': None
        }

        try:
            from PIL import Image, ImageChops

            original = Image.open(file_path).convert('RGB')

            # Re-save at quality 95
            buffer = io.BytesIO()
            original.save(buffer, 'JPEG', quality=95)
            buffer.seek(0)
            resaved = Image.open(buffer).convert('RGB')

            # Calculate difference
            diff = ImageChops.difference(original, resaved)

            # Amplify differences (scale by 20x for visibility)
            extrema = diff.getextrema()
            max_diff = max(max(channel) for channel in extrema)
            ela_results['max_difference'] = max_diff

            # Calculate mean difference across all pixels
            pixels = list(diff.getdata())
            if pixels:
                total = sum(sum(p) for p in pixels)
                mean = total / (len(pixels) * 3)  # 3 channels
                ela_results['mean_difference'] = round(mean, 4)

            # Count suspicious regions (pixels with high difference)
            threshold = 50
            suspicious = sum(
                1 for p in pixels
                if any(c > threshold for c in p)
            )
            ela_results['suspicious_regions'] = suspicious

            # Determine manipulation likelihood
            suspicious_ratio = suspicious / max(len(pixels), 1)
            if suspicious_ratio > 0.1:
                ela_results['manipulation_likelihood'] = 'high'
            elif suspicious_ratio > 0.03:
                ela_results['manipulation_likelihood'] = 'medium'
            elif suspicious_ratio > 0.005:
                ela_results['manipulation_likelihood'] = 'low'
            else:
                ela_results['manipulation_likelihood'] = 'very_low'

            # Save ELA image
            try:
                ela_dir = os.path.join(os.path.dirname(file_path), 'ela_output')
                os.makedirs(ela_dir, exist_ok=True)
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                ela_path = os.path.join(ela_dir, f'{base_name}_ela.png')

                # Amplify and save
                scale = 20
                ela_image = diff.point(lambda x: min(x * scale, 255))
                ela_image.save(ela_path)
                ela_results['ela_image_path'] = ela_path
            except Exception as e:
                logger.warning(f"Could not save ELA image: {e}")

            ela_results['performed'] = True

        except ImportError:
            ela_results['error'] = 'Pillow library not available'
            logger.error("Pillow is required for ELA")
        except Exception as e:
            ela_results['error'] = f'ELA failed: {str(e)}'
            logger.error(f"ELA error for {file_path}: {e}")

        return ela_results

    def extract_text_ocr(self, file_path: str) -> Optional[str]:
        """
        Extract text from image using OCR (placeholder for pytesseract).

        Args:
            file_path: Path to the image file

        Returns:
            Extracted text string or None
        """
        try:
            import pytesseract
            from PIL import Image

            img = Image.open(file_path)
            text = pytesseract.image_to_string(img)
            return text.strip() if text.strip() else None
        except ImportError:
            logger.debug("pytesseract not available for OCR")
            return None
        except Exception as e:
            logger.error(f"OCR extraction failed for {file_path}: {e}")
            return None

    def analyze_document(self, file_path: str) -> Dict:
        """
        Analyze document metadata for PDFs and DOCX files.

        Args:
            file_path: Path to the document file

        Returns:
            Dict with document metadata
        """
        self.start_time = time.time()
        self.results['file_path'] = file_path
        self.results['metadata']['analyzed_at'] = datetime.utcnow().isoformat()

        ext = os.path.splitext(file_path)[1].lower()
        self.results['file_type'] = ext

        # File hashes
        try:
            self.results['file_hash'] = self._calculate_file_hashes(file_path)
        except Exception as e:
            logger.error(f"File hash calculation failed: {e}")

        doc_meta = {
            'title': None,
            'author': None,
            'creator': None,
            'producer': None,
            'subject': None,
            'creation_date': None,
            'modification_date': None,
            'page_count': None,
            'word_count': None,
            'error': None
        }

        try:
            if ext == '.pdf':
                doc_meta = self._analyze_pdf(file_path)
            elif ext in ('.docx', '.doc'):
                doc_meta = self._analyze_docx(file_path)
            else:
                doc_meta['error'] = f'Unsupported document type: {ext}'
        except Exception as e:
            doc_meta['error'] = f'Document analysis failed: {str(e)}'
            logger.error(f"Document analysis error for {file_path}: {e}")

        self.results['document_metadata'] = doc_meta

        # Risk score
        try:
            risk_data = self.calculate_risk_score(self.results)
            self.results['risk_score'] = risk_data['score']
            self.results['risk_factors'] = risk_data['factors']
        except Exception as e:
            logger.error(f"Risk calculation failed: {e}")

        self.results['metadata']['analysis_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def _analyze_pdf(self, file_path: str) -> Dict:
        """Extract metadata from a PDF file using PyPDF2."""
        meta = {
            'title': None,
            'author': None,
            'creator': None,
            'producer': None,
            'subject': None,
            'creation_date': None,
            'modification_date': None,
            'page_count': None,
            'error': None
        }

        try:
            from PyPDF2 import PdfReader

            reader = PdfReader(file_path)
            meta['page_count'] = len(reader.pages)

            info = reader.metadata
            if info:
                meta['title'] = info.get('/Title', info.title) if info else None
                meta['author'] = info.get('/Author', info.author) if info else None
                meta['creator'] = info.get('/Creator', info.creator) if info else None
                meta['producer'] = info.get('/Producer', info.producer) if info else None
                meta['subject'] = info.get('/Subject', info.subject) if info else None
                meta['creation_date'] = str(info.get('/CreationDate', '')) if info else None
                meta['modification_date'] = str(info.get('/ModDate', '')) if info else None

        except ImportError:
            meta['error'] = 'PyPDF2 library not available'
            logger.error("PyPDF2 is required for PDF analysis")
        except Exception as e:
            meta['error'] = f'PDF analysis failed: {str(e)}'
            logger.error(f"PDF analysis error: {e}")

        return meta

    def _analyze_docx(self, file_path: str) -> Dict:
        """Extract metadata from a DOCX file using python-docx."""
        meta = {
            'title': None,
            'author': None,
            'creator': None,
            'subject': None,
            'creation_date': None,
            'modification_date': None,
            'last_modified_by': None,
            'revision': None,
            'word_count': None,
            'page_count': None,
            'error': None
        }

        try:
            from docx import Document

            doc = Document(file_path)
            props = doc.core_properties

            meta['title'] = props.title
            meta['author'] = props.author
            meta['creator'] = props.author  # Same as author in DOCX
            meta['subject'] = props.subject
            meta['creation_date'] = props.created.isoformat() if props.created else None
            meta['modification_date'] = props.modified.isoformat() if props.modified else None
            meta['last_modified_by'] = props.last_modified_by
            meta['revision'] = props.revision

            # Count words
            text = ' '.join(p.text for p in doc.paragraphs)
            meta['word_count'] = len(text.split()) if text else 0

        except ImportError:
            meta['error'] = 'python-docx library not available'
            logger.error("python-docx is required for DOCX analysis")
        except Exception as e:
            meta['error'] = f'DOCX analysis failed: {str(e)}'
            logger.error(f"DOCX analysis error: {e}")

        return meta

    def calculate_risk_score(self, analysis: Dict) -> Dict:
        """
        Calculate manipulation risk score based on forensic analysis.

        Args:
            analysis: Complete analysis results dict

        Returns:
            Dict with score (0-100) and risk factors
        """
        score = 0
        factors = []

        # EXIF stripped (common in manipulated images)
        exif = analysis.get('exif_data', {})
        if exif.get('error') == 'No EXIF data found':
            score += 15
            factors.append('No EXIF metadata (may have been stripped)')

        # Software indicates editing
        software = exif.get('software', '') or ''
        editing_software = ['photoshop', 'gimp', 'lightroom', 'pixlr', 'canva',
                            'aftereffect', 'premiere', 'paint.net']
        for sw in editing_software:
            if sw in software.lower():
                score += 20
                factors.append(f'Edited with {software}')
                break

        # Date inconsistencies
        dt_original = exif.get('datetime_original')
        dt_modified = exif.get('datetime_modified')
        if dt_original and dt_modified and dt_original != dt_modified:
            score += 10
            factors.append('Original and modified dates differ')

        # ELA results
        ela = analysis.get('ela_results', {})
        if ela.get('performed'):
            likelihood = ela.get('manipulation_likelihood', 'unknown')
            if likelihood == 'high':
                score += 35
                factors.append('High ELA manipulation likelihood')
            elif likelihood == 'medium':
                score += 20
                factors.append('Medium ELA manipulation likelihood')
            elif likelihood == 'low':
                score += 5
                factors.append('Low ELA manipulation likelihood')

        # GPS data present (could be location evidence)
        gps = analysis.get('gps_data', {})
        if gps.get('has_gps'):
            # GPS present is informational, not necessarily risky
            factors.append('GPS coordinates found in image')

        score = min(score, 100)

        return {'score': score, 'factors': factors}


def analyze_image(file_path: str) -> Dict:
    """
    Convenience function to analyze an image file.

    Args:
        file_path: Path to the image file

    Returns:
        Dict with analysis results
    """
    forensics = ImageForensics()
    return forensics.analyze_image(file_path)


def analyze_document(file_path: str) -> Dict:
    """
    Convenience function to analyze a document file.

    Args:
        file_path: Path to the document file

    Returns:
        Dict with analysis results
    """
    forensics = ImageForensics()
    return forensics.analyze_document(file_path)
